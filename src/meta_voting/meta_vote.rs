// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(any(test, feature = "testing"))]
use super::{
    bool_set::BoolSet,
    meta_vote_values::{AuxValue, BinValues, Estimates, UndecidedMetaVoteValues},
};
use super::{
    meta_vote_counts::MetaVoteCounts,
    meta_vote_values::{MetaVoteValues, Step},
};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
    num::NonZeroUsize,
};

// This holds the state of a (binary) meta vote about which we're trying to achieve consensus.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MetaVote {
    pub round: usize,
    pub step: Step,
    pub values: MetaVoteValues,
}

impl Debug for MetaVote {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{{ {}/{:?}, ", self.round, self.step)?;
        write!(f, "{:?}", self.values)?;
        write!(f, "}}")
    }
}

impl MetaVote {
    #[cfg(any(test, feature = "testing"))]
    pub fn new(
        round: usize,
        step: Step,
        estimates: BoolSet,
        bin_values: BoolSet,
        aux_value: Option<bool>,
        decision: Option<bool>,
    ) -> Self {
        let values = match decision {
            Some(values) => MetaVoteValues::Decided(values),
            None => MetaVoteValues::Undecided(UndecidedMetaVoteValues::new(
                Estimates::new(estimates),
                BinValues::new(bin_values),
                AuxValue::new(aux_value),
            )),
        };
        MetaVote {
            round,
            step,
            values,
        }
    }

    pub fn new_for_observer(
        initial_estimate: bool,
        others: &[&[MetaVote]],
        total_peers: NonZeroUsize,
    ) -> Vec<Self> {
        let initial = Self {
            values: MetaVoteValues::from_initial_estimate(initial_estimate),
            ..Default::default()
        };
        Self::next_votes(&[initial], others, &BTreeMap::new(), total_peers)
    }

    /// Create temporary next meta-votes. They must be finalized by calling `next_final` before
    /// passing them to `MetaEvent`.
    pub fn next_temp(
        parent: &[MetaVote],
        others: &[&[MetaVote]],
        total_peers: NonZeroUsize,
    ) -> Vec<Self> {
        Self::next_votes(parent, others, &BTreeMap::new(), total_peers)
    }

    /// Finalize temporary meta-votes.
    pub fn next_final(
        temp: &[MetaVote],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: NonZeroUsize,
    ) -> Vec<Self> {
        Self::next_votes(temp, &[], coin_tosses, total_peers)
    }

    pub fn decision(&self) -> Option<bool> {
        match self.values {
            MetaVoteValues::Decided(value) => Some(value),
            MetaVoteValues::Undecided(_) => None,
        }
    }

    fn next_votes(
        prev: &[MetaVote],
        others: &[&[MetaVote]],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: NonZeroUsize,
    ) -> Vec<Self> {
        let mut next = Vec::new();
        for vote in prev {
            let counts = MetaVoteCounts::new(vote, others, total_peers);
            let mut updated = *vote;
            updated.update(counts, &coin_tosses);
            let decided = vote.is_decided();
            next.push(updated);
            if decided {
                break;
            }
        }

        while let Some(next_meta_vote) =
            Self::next_vote(next.last(), others, &coin_tosses, total_peers)
        {
            next.push(next_meta_vote);
        }

        next
    }

    pub fn round_and_step(&self) -> (usize, Step) {
        (self.round, self.step)
    }

    fn is_decided(&self) -> bool {
        if let MetaVoteValues::Decided(_) = self.values {
            true
        } else {
            false
        }
    }

    fn update(&mut self, counts: MetaVoteCounts, coin_tosses: &BTreeMap<usize, bool>) {
        let coin_toss = coin_tosses.get(&self.round).cloned();
        self.values.update(counts, coin_toss, self.step);
    }

    fn next_vote(
        parent: Option<&Self>,
        others: &[&[MetaVote]],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: NonZeroUsize,
    ) -> Option<MetaVote> {
        let parent = parent?;

        if parent.is_decided() {
            return None;
        }
        let counts = MetaVoteCounts::new(parent, others, total_peers);
        if counts.is_supermajority(counts.aux_values_set()) {
            let coin_toss = coin_tosses.get(&parent.round);
            let mut next = parent.increase_step(&counts, coin_toss.cloned());
            let new_counts = MetaVoteCounts::new(&next, others, total_peers);
            next.update(new_counts, &coin_tosses);
            Some(next)
        } else {
            None
        }
    }

    fn increase_step(&self, counts: &MetaVoteCounts, coin_toss: Option<bool>) -> Self {
        let mut next = *self;
        next.values.increase_step(counts, coin_toss, self.step);
        match next.step {
            Step::ForcedTrue => {
                next.step = Step::ForcedFalse;
            }
            Step::ForcedFalse => {
                next.step = Step::GenuineFlip;
            }
            Step::GenuineFlip => {
                next.step = Step::ForcedTrue;
                next.round += 1;
            }
        }
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::meta_voting::meta_vote_values::{AuxValue, BinValues, Estimates};
    use std::num::NonZeroUsize;

    #[test]
    fn meta_vote_decide_if_any_decided() {
        let mut collected_votes = vec![];
        let mut others = vec![];
        let decided_meta_vote = MetaVote {
            round: 0,
            step: Step::ForcedTrue,
            values: MetaVoteValues::Decided(true),
        };
        let total_peers = 7;

        collected_votes.push(vec![decided_meta_vote]);

        let undecided_meta_vote = MetaVote {
            round: 0,
            step: Step::ForcedTrue,
            values: MetaVoteValues::Undecided(UndecidedMetaVoteValues::default()),
        };
        for _ in 1..total_peers - 1 {
            collected_votes.push(vec![undecided_meta_vote]);
        }

        for votes in collected_votes.iter() {
            others.push(votes.as_slice());
        }
        let result = MetaVote::new_for_observer(
            true,
            others.as_slice(),
            NonZeroUsize::new(total_peers).unwrap(),
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], decided_meta_vote);
    }

    #[test]
    fn meta_vote_progressing_step() {
        let mut collected_votes = vec![];
        let mut others = vec![];

        let total_peers = 7;
        let undecided_meta_vote = MetaVote {
            round: 0,
            step: Step::ForcedTrue,
            values: MetaVoteValues::Undecided(UndecidedMetaVoteValues::new(
                Estimates::new(BoolSet::Both),
                BinValues::new(BoolSet::Both),
                AuxValue::new(Some(false)),
            )),
        };
        for _ in 0..total_peers - 1 {
            collected_votes.push(vec![undecided_meta_vote]);
        }

        for votes in collected_votes.iter() {
            others.push(votes.as_slice());
        }
        let result = MetaVote::new_for_observer(
            true,
            others.as_slice(),
            NonZeroUsize::new(total_peers).unwrap(),
        );
        assert_eq!(result.len(), 2);
        let expected_meta_votes = vec![
            MetaVote {
                round: 0,
                step: Step::ForcedTrue,
                values: MetaVoteValues::Undecided(UndecidedMetaVoteValues::new(
                    Estimates::new(BoolSet::Both),
                    BinValues::new(BoolSet::Both),
                    AuxValue::new(Some(true)),
                )),
            },
            MetaVote {
                round: 0,
                step: Step::ForcedFalse,
                values: MetaVoteValues::Undecided(UndecidedMetaVoteValues::new(
                    Estimates::new(BoolSet::Single(false)),
                    BinValues::new(BoolSet::Empty),
                    AuxValue::new(None),
                )),
            },
        ];
        assert_eq!(result, expected_meta_votes);
    }

    #[test]
    fn meta_vote_reach_decision() {
        let mut collected_votes = vec![];
        let mut others = vec![];

        let total_peers = 7;
        let undecided_meta_vote_1 = MetaVote {
            round: 0,
            step: Step::ForcedTrue,
            values: MetaVoteValues::Undecided(UndecidedMetaVoteValues::new(
                Estimates::new(BoolSet::Both),
                BinValues::new(BoolSet::Both),
                AuxValue::new(Some(false)),
            )),
        };
        let undecided_meta_vote_2 = MetaVote {
            round: 0,
            step: Step::ForcedFalse,
            values: MetaVoteValues::Undecided(UndecidedMetaVoteValues::new(
                Estimates::new(BoolSet::Single(false)),
                BinValues::new(BoolSet::Single(false)),
                AuxValue::new(Some(false)),
            )),
        };
        for _ in 0..total_peers - 1 {
            collected_votes.push(vec![undecided_meta_vote_1, undecided_meta_vote_2]);
        }

        for votes in collected_votes.iter() {
            others.push(votes.as_slice());
        }
        let result = MetaVote::new_for_observer(
            true,
            others.as_slice(),
            NonZeroUsize::new(total_peers).unwrap(),
        );
        assert_eq!(result.len(), 2);
        let expected_meta_votes = vec![
            MetaVote {
                round: 0,
                step: Step::ForcedTrue,
                values: MetaVoteValues::Undecided(UndecidedMetaVoteValues::new(
                    Estimates::new(BoolSet::Both),
                    BinValues::new(BoolSet::Both),
                    AuxValue::new(Some(true)),
                )),
            },
            MetaVote {
                round: 0,
                step: Step::ForcedFalse,
                values: MetaVoteValues::Decided(false),
            },
        ];
        assert_eq!(result, expected_meta_votes);
    }
}
