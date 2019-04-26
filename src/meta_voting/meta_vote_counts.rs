// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::meta_vote::MetaVote;
use crate::observation::is_more_than_two_thirds;
use std::iter;
use std::num::NonZeroUsize;

// This is used to collect the meta votes of other events relating to a single (binary) meta vote at
// a given round and step.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MetaVoteCounts {
    pub estimates_true: usize,
    pub estimates_false: usize,
    pub bin_values_true: usize,
    pub bin_values_false: usize,
    pub aux_values_true: usize,
    pub aux_values_false: usize,
    pub decision: Option<bool>,
    pub total_peers: NonZeroUsize,
}

impl MetaVoteCounts {
    // Construct a `MetaVoteCounts` by collecting details from all meta votes which are for the
    // given `parent`'s `round` and `step`.  These results will include info from our own `parent`
    // meta vote.
    pub fn new(parent: &MetaVote, others: &[&[MetaVote]], total_peers: NonZeroUsize) -> Self {
        let mut counts = MetaVoteCounts::default();
        counts.total_peers = total_peers;
        for vote in others
            .iter()
            .filter_map(|other| {
                other
                    .iter()
                    .filter(|vote| vote.round_and_step() == parent.round_and_step())
                    .last()
            })
            .chain(iter::once(parent))
        {
            if vote.estimates.contains(true) {
                counts.estimates_true += 1;
            }
            if vote.estimates.contains(false) {
                counts.estimates_false += 1;
            }
            if vote.bin_values.contains(true) {
                counts.bin_values_true += 1;
            }
            if vote.bin_values.contains(false) {
                counts.bin_values_false += 1;
            }
            match vote.aux_value {
                Some(true) => counts.aux_values_true += 1,
                Some(false) => counts.aux_values_false += 1,
                None => (),
            }

            if counts.decision.is_none() {
                counts.decision = vote.decision;
            }
        }

        counts
    }

    pub fn aux_values_set(&self) -> usize {
        self.aux_values_true + self.aux_values_false
    }

    pub fn is_supermajority(&self, count: usize) -> bool {
        is_more_than_two_thirds(count, self.total_peers())
    }

    pub fn is_at_least_one_third(&self, count: usize) -> bool {
        3 * count >= self.total_peers()
    }

    pub fn check_exceeding(&self) {
        let is_exceeding = self.estimates_true > self.total_peers()
            || self.estimates_false > self.total_peers()
            || self.bin_values_true > self.total_peers()
            || self.bin_values_false > self.total_peers()
            || self.aux_values_true > self.total_peers()
            || self.aux_values_false > self.total_peers();

        if is_exceeding {
            log_or_panic!("Having count exceeding total peers {:?}", self);
        }
    }

    fn total_peers(&self) -> usize {
        self.total_peers.get()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{BoolSet, Step},
        *,
    };
    use std::{iter, slice};

    #[test]
    fn count_estimates() {
        let total_peers = NonZeroUsize::new(4).unwrap();

        let actual = counts_with_estimates(1, 0, 0, 0, total_peers);
        let expected = MetaVoteCounts {
            estimates_true: 0,
            estimates_false: 0,
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);

        let actual = counts_with_estimates(0, 1, 0, 0, total_peers);
        let expected = MetaVoteCounts {
            estimates_true: 1,
            estimates_false: 0,
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);

        let actual = counts_with_estimates(0, 0, 1, 0, total_peers);
        let expected = MetaVoteCounts {
            estimates_true: 0,
            estimates_false: 1,
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);

        let actual = counts_with_estimates(0, 0, 0, 1, total_peers);
        let expected = MetaVoteCounts {
            estimates_true: 1,
            estimates_false: 1,
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);

        let actual = counts_with_estimates(1, 1, 1, 1, total_peers);
        let expected = MetaVoteCounts {
            estimates_true: 2,
            estimates_false: 2,
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);

        let actual = counts_with_estimates(1, 2, 3, 1, total_peers);
        let expected = MetaVoteCounts {
            estimates_true: 3,
            estimates_false: 4,
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn count_aux_values() {
        let total_peers = NonZeroUsize::new(4).unwrap();

        let actual = counts_with_aux_values(1, 0, 0, total_peers);
        let expected = MetaVoteCounts {
            aux_values_true: 0,
            aux_values_false: 0,
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);

        let actual = counts_with_aux_values(0, 1, 0, total_peers);
        let expected = MetaVoteCounts {
            aux_values_true: 1,
            aux_values_false: 0,
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);

        let actual = counts_with_aux_values(0, 0, 1, total_peers);
        let expected = MetaVoteCounts {
            aux_values_true: 0,
            aux_values_false: 1,
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);

        let actual = counts_with_aux_values(1, 2, 3, total_peers);
        let expected = MetaVoteCounts {
            aux_values_true: 2,
            aux_values_false: 3,
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn count_decision() {
        let total_peers = NonZeroUsize::new(4).unwrap();

        let actual = counts_with_decisions(&[None], total_peers);
        let expected = MetaVoteCounts {
            decision: None,
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);

        let actual = counts_with_decisions(&[Some(false)], total_peers);
        let expected = MetaVoteCounts {
            decision: Some(false),
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);

        let actual = counts_with_decisions(&[Some(true)], total_peers);
        let expected = MetaVoteCounts {
            decision: Some(true),
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);

        // Only the first non-none decision counts.
        let actual = counts_with_decisions(&[None, Some(true), Some(false)], total_peers);
        let expected = MetaVoteCounts {
            decision: Some(true),
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);

        let actual = counts_with_decisions(&[None, Some(false), Some(true)], total_peers);
        let expected = MetaVoteCounts {
            decision: Some(false),
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);

        let actual = counts_with_decisions(&[Some(true), None], total_peers);
        let expected = MetaVoteCounts {
            decision: Some(true),
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected)
    }

    #[test]
    fn only_votes_with_the_same_round_and_step_as_parent_are_counted() {
        let total_peers = NonZeroUsize::new(4).unwrap();

        let parent_vote = MetaVote {
            step: Step::ForcedTrue,
            ..MetaVote::default()
        };
        let vote0 = MetaVote {
            step: Step::ForcedTrue,
            estimates: BoolSet::Single(true),
            ..MetaVote::default()
        };
        let vote1 = MetaVote {
            step: Step::ForcedFalse,
            estimates: BoolSet::Single(true),
            ..MetaVote::default()
        };
        let vote2 = MetaVote {
            step: Step::ForcedTrue,
            estimates: BoolSet::Single(true),
            ..MetaVote::default()
        };
        let vote3 = MetaVote {
            step: Step::ForcedFalse,
            estimates: BoolSet::Single(true),
            ..MetaVote::default()
        };

        let actual = MetaVoteCounts::new(
            &parent_vote,
            &[&[vote0], &[vote1], &[vote2, vote3]],
            total_peers,
            true,
        );
        let expected = MetaVoteCounts {
            estimates_true: 2,
            ..default_counts(total_peers)
        };
        assert_eq!(actual, expected);
    }

    fn default_counts(total_peers: NonZeroUsize) -> MetaVoteCounts {
        MetaVoteCounts {
            estimates_true: 0,
            estimates_false: 0,
            bin_values_true: 0,
            bin_values_false: 0,
            aux_values_true: 0,
            aux_values_false: 0,
            decision: None,
            total_peers,
        }
    }

    fn counts_with_estimates(
        num_empty: usize,
        num_true: usize,
        num_false: usize,
        num_both: usize,
        total_peers: NonZeroUsize,
    ) -> MetaVoteCounts {
        let repeat_votes = |count, estimates| {
            iter::repeat(MetaVote {
                estimates,
                ..MetaVote::default()
            })
            .take(count)
        };

        let votes: Vec<_> = repeat_votes(num_empty, BoolSet::Empty)
            .chain(repeat_votes(num_true, BoolSet::Single(true)))
            .chain(repeat_votes(num_false, BoolSet::Single(false)))
            .chain(repeat_votes(num_both, BoolSet::Both))
            .collect();

        counts_with_votes(&votes, total_peers)
    }

    fn counts_with_aux_values(
        num_empty: usize,
        num_true: usize,
        num_false: usize,
        total_peers: NonZeroUsize,
    ) -> MetaVoteCounts {
        let repeat_votes = |count, aux_value| {
            iter::repeat(MetaVote {
                aux_value,
                ..MetaVote::default()
            })
            .take(count)
        };

        let votes: Vec<_> = repeat_votes(num_empty, None)
            .chain(repeat_votes(num_true, Some(true)))
            .chain(repeat_votes(num_false, Some(false)))
            .collect();

        counts_with_votes(&votes, total_peers)
    }

    fn counts_with_decisions(
        decisions: &[Option<bool>],
        total_peers: NonZeroUsize,
    ) -> MetaVoteCounts {
        let votes: Vec<_> = decisions
            .iter()
            .cloned()
            .map(|decision| MetaVote {
                decision,
                ..MetaVote::default()
            })
            .collect();
        counts_with_votes(&votes, total_peers)
    }

    fn counts_with_votes(votes: &[MetaVote], total_peers: NonZeroUsize) -> MetaVoteCounts {
        let parent_vote = MetaVote::default();
        let votes: Vec<_> = votes.iter().map(slice::from_ref).collect();
        MetaVoteCounts::new(&parent_vote, votes.as_slice(), total_peers, false)
    }
}
