// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod bool_set;
mod meta_election;
mod meta_event;
mod meta_vote;
mod meta_vote_counts;
mod meta_vote_values;

#[cfg(any(all(test, feature = "mock"), feature = "dump-graphs"))]
pub(crate) use self::meta_election::snapshot::MetaElectionSnapshot;
#[cfg(any(all(test, feature = "mock"), feature = "testing"))]
pub(crate) use self::meta_election::UnconsensusedEvents;
#[cfg(any(test, feature = "testing"))]
pub(crate) use self::{bool_set::BoolSet, meta_vote_values::Step};
pub(crate) use self::{
    meta_election::MetaElection,
    meta_event::{MetaEvent, MetaEventBuilder, Observer},
    meta_vote::MetaVote,
};
