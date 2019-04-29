// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{bool_set::BoolSet, meta_vote_counts::MetaVoteCounts};
use std::fmt::{self, Debug, Formatter};
use std::num::NonZeroUsize;

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Estimates(BoolSet);

impl Debug for Estimates {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write_multiple_bool_values(f, "est", self.0)
    }
}

impl Estimates {
    #[cfg(any(test, feature = "testing"))]
    pub fn new(estimates: BoolSet) -> Self {
        Estimates(estimates)
    }

    fn from_initial_value(value: bool) -> Self {
        Estimates(BoolSet::Single(value))
    }

    fn calculate(&mut self, counts: &mut MetaVoteCounts, coin_toss: Option<bool>) {
        if self.0.is_empty() {
            if let Some(toss) = coin_toss {
                if toss {
                    counts.estimates_true += 1;
                } else {
                    counts.estimates_false += 1;
                }
                self.0 = BoolSet::Single(toss);
            }
        } else {
            if counts.is_at_least_one_third(counts.estimates_true) && self.0.insert(true) {
                counts.estimates_true += 1;
            }
            if counts.is_at_least_one_third(counts.estimates_false) && self.0.insert(false) {
                counts.estimates_false += 1;
            }
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BinValues(BoolSet);

impl Debug for BinValues {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write_multiple_bool_values(f, "bin", self.0)
    }
}

impl BinValues {
    #[cfg(any(test, feature = "testing"))]
    pub fn new(bin_values: BoolSet) -> Self {
        BinValues(bin_values)
    }

    fn calculate(&mut self, counts: &mut MetaVoteCounts) {
        if counts.is_supermajority(counts.estimates_true) && self.0.insert(true) {
            counts.bin_values_true += 1;
        }
        if counts.is_supermajority(counts.estimates_false) && self.0.insert(false) {
            counts.bin_values_false += 1;
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AuxValue(Option<bool>);

impl Debug for AuxValue {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write_optional_single_bool_value(f, "aux", self.0)
    }
}

impl AuxValue {
    #[cfg(any(test, feature = "testing"))]
    pub fn new(aux_value: Option<bool>) -> Self {
        AuxValue(aux_value)
    }

    fn calculate(
        &mut self,
        counts: &mut MetaVoteCounts,
        bin_values_before_update: BinValues,
        bin_values_now: BinValues,
    ) {
        if self.0.is_some() {
            return;
        }
        let bin_values_was_empty = bin_values_before_update.0.is_empty();
        if bin_values_was_empty {
            if bin_values_now.0.len() == 1 {
                if bin_values_now.0.contains(true) {
                    self.0 = Some(true);
                    counts.aux_values_true += 1;
                } else {
                    self.0 = Some(false);
                    counts.aux_values_false += 1;
                }
            } else if bin_values_now.0.len() == 2 {
                self.0 = Some(true);
                counts.aux_values_true += 1;
            }
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UndecidedMetaVoteValues {
    estimates: Estimates,
    bin_values: BinValues,
    aux_value: AuxValue,
}

impl Debug for UndecidedMetaVoteValues {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{:?}{:?}{:?}",
            self.estimates, self.bin_values, self.aux_value
        )
    }
}

impl UndecidedMetaVoteValues {
    #[cfg(any(test, feature = "testing"))]
    pub fn new(estimates: Estimates, bin_values: BinValues, aux_value: AuxValue) -> Self {
        UndecidedMetaVoteValues {
            estimates,
            bin_values,
            aux_value,
        }
    }

    fn from_decided_meta_vote(value: bool) -> Self {
        Self {
            estimates: Estimates(BoolSet::Single(value)),
            bin_values: BinValues(BoolSet::Single(value)),
            aux_value: AuxValue(Some(value)),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum MetaVoteValues {
    Decided(bool),
    Undecided(UndecidedMetaVoteValues),
}

impl Debug for MetaVoteValues {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            MetaVoteValues::Decided(value) => {
                write!(
                    f,
                    "{:?}",
                    UndecidedMetaVoteValues::from_decided_meta_vote(*value)
                )?;
                write_optional_single_bool_value(f, "dec", Some(*value))
            }
            MetaVoteValues::Undecided(values) => {
                write!(f, "{:?}", values)?;
                write_optional_single_bool_value(f, "dec", None)
            }
        }
    }
}

impl MetaVoteValues {
    pub fn from_initial_estimate(value: bool) -> Self {
        let mut values = UndecidedMetaVoteValues::default();
        values.estimates = Estimates::from_initial_value(value);
        MetaVoteValues::Undecided(values)
    }

    pub fn count(self, total_peers: NonZeroUsize) -> MetaVoteCounts {
        // Counts the contribution of these MetaVoteValues
        let mut counts = MetaVoteCounts::default_counts(total_peers);
        match self {
            MetaVoteValues::Decided(value) => {
                counts.decision = Some(value);
                if value {
                    counts.estimates_true = 1;
                    counts.bin_values_true = 1;
                    counts.aux_values_true = 1;
                } else {
                    counts.estimates_false = 1;
                    counts.bin_values_false = 1;
                    counts.aux_values_false = 1;
                }
            }
            MetaVoteValues::Undecided(values) => {
                if values.estimates.0.contains(true) {
                    counts.estimates_true = 1;
                }
                if values.estimates.0.contains(false) {
                    counts.estimates_false = 1;
                }
                if values.bin_values.0.contains(true) {
                    counts.bin_values_true = 1;
                }
                if values.bin_values.0.contains(false) {
                    counts.bin_values_false = 1;
                }
                match values.aux_value.0 {
                    Some(true) => counts.aux_values_true = 1,
                    Some(false) => counts.aux_values_false = 1,
                    None => (),
                }
            }
        }
        counts
    }

    fn calculate_new_estimates(&mut self, counts: &mut MetaVoteCounts, coin_toss: Option<bool>) {
        if let MetaVoteValues::Undecided(values) = self {
            values.estimates.calculate(counts, coin_toss);
        }
    }

    fn calculate_new_bin_values(&mut self, counts: &mut MetaVoteCounts) {
        if let MetaVoteValues::Undecided(values) = self {
            values.bin_values.calculate(counts);
        }
    }

    fn calculate_new_auxiliary_value(
        &mut self,
        counts: &mut MetaVoteCounts,
        bin_values_before_update: BinValues,
    ) {
        if let MetaVoteValues::Undecided(values) = self {
            let bin_values_now = values.bin_values;
            values
                .aux_value
                .calculate(counts, bin_values_before_update, bin_values_now);
        }
    }

    fn calculate_new_decision(&mut self, counts: &MetaVoteCounts, step: Step) {
        if let MetaVoteValues::Undecided(values) = *self {
            let bin_values = values.bin_values;
            let decision = match step {
                Step::ForcedTrue => {
                    if bin_values.0.contains(true)
                        && counts.is_supermajority(counts.aux_values_true)
                    {
                        Some(true)
                    } else {
                        counts.decision
                    }
                }
                Step::ForcedFalse => {
                    if bin_values.0.contains(false)
                        && counts.is_supermajority(counts.aux_values_false)
                    {
                        Some(false)
                    } else {
                        counts.decision
                    }
                }
                Step::GenuineFlip => counts.decision,
            };
            if let Some(value) = decision {
                *self = MetaVoteValues::Decided(value);
            }
        }
    }

    pub fn increase_step(&mut self, counts: &MetaVoteCounts, coin_toss: Option<bool>, step: Step) {
        if let MetaVoteValues::Undecided(ref mut values) = *self {
            // Set the estimates as per the concrete coin toss rules.
            values.estimates.0 = match step {
                Step::ForcedTrue => {
                    if counts.is_supermajority(counts.aux_values_false) {
                        BoolSet::Single(false)
                    } else {
                        BoolSet::Single(true)
                    }
                }
                Step::ForcedFalse => {
                    if counts.is_supermajority(counts.aux_values_true) {
                        BoolSet::Single(true)
                    } else {
                        BoolSet::Single(false)
                    }
                }
                Step::GenuineFlip => {
                    if counts.is_supermajority(counts.aux_values_true) {
                        BoolSet::Single(true)
                    } else if counts.is_supermajority(counts.aux_values_false) {
                        BoolSet::Single(false)
                    } else if let Some(coin_toss) = coin_toss {
                        BoolSet::Single(coin_toss)
                    } else {
                        // Clear the estimates to indicate we're waiting for further events to be
                        // gossiped to try and get the coin toss result.
                        BoolSet::Empty
                    }
                }
            };
            values.bin_values.0 = BoolSet::Empty;
            values.aux_value.0 = None;
        }
    }

    pub fn update(&mut self, mut counts: MetaVoteCounts, coin_toss: Option<bool>, step: Step) {
        *self = match self {
            MetaVoteValues::Decided(_) => *self,
            MetaVoteValues::Undecided(ref values) => {
                let mut updated = *self;
                updated.calculate_new_estimates(&mut counts, coin_toss);
                let bin_values_before_update = values.bin_values;
                updated.calculate_new_bin_values(&mut counts);
                updated.calculate_new_auxiliary_value(&mut counts, bin_values_before_update);
                counts.check_exceeding();
                updated.calculate_new_decision(&counts, step);
                updated
            }
        }
    }

    #[cfg(feature = "dump-graphs")]
    pub fn as_chars(self) -> (char, char, char, char) {
        let pretty_bool = |b: bool| {
            if b {
                't'
            } else {
                'f'
            }
        };
        let pretty_option_bool = |o: Option<bool>| match o {
            Some(b) => pretty_bool(b),
            None => '-',
        };
        let pretty_bool_set = |s: BoolSet| match s {
            BoolSet::Empty => '-',
            BoolSet::Single(b) => pretty_bool(b),
            BoolSet::Both => 'b',
        };

        match self {
            MetaVoteValues::Decided(value) => {
                let dec = pretty_bool(value);
                (dec, dec, dec, dec)
            }
            MetaVoteValues::Undecided(values) => {
                let est = pretty_bool_set(values.estimates.0);
                let bin = pretty_bool_set(values.bin_values.0);
                let aux = pretty_option_bool(values.aux_value.0);
                let dec = pretty_option_bool(None);
                (est, bin, aux, dec)
            }
        }
    }
}

impl Default for MetaVoteValues {
    fn default() -> Self {
        MetaVoteValues::Undecided(Default::default())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
pub(crate) enum Step {
    ForcedTrue,
    ForcedFalse,
    GenuineFlip,
}

impl Default for Step {
    fn default() -> Step {
        Step::ForcedTrue
    }
}

impl Debug for Step {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let step = match self {
            Step::ForcedTrue => 0,
            Step::ForcedFalse => 1,
            Step::GenuineFlip => 2,
        };
        write!(f, "{}", step)
    }
}

fn write_bool(f: &mut Formatter, a_bool: bool) -> fmt::Result {
    if a_bool {
        write!(f, "t")
    } else {
        write!(f, "f")
    }
}

fn write_multiple_bool_values(f: &mut Formatter, field: &str, input: BoolSet) -> fmt::Result {
    write!(f, "{}:{{", field)?;
    match input {
        BoolSet::Empty => (),
        BoolSet::Single(ref s) => {
            write_bool(f, *s)?;
        }
        BoolSet::Both => {
            write_bool(f, true)?;
            write!(f, ", ")?;
            write_bool(f, false)?;
        }
    }
    write!(f, "}} ")
}

fn write_optional_single_bool_value(
    f: &mut Formatter,
    field: &str,
    value: Option<bool>,
) -> fmt::Result {
    write!(f, "{}:{{", field)?;
    if let Some(vote) = value {
        write_bool(f, vote)?;
    }
    write!(f, "}} ")
}
