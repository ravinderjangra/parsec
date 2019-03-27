// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Event;
use crate::{
    id::SecretId,
    peer_list::{PeerIndex, PeerIndexMap, PeerList},
};
use itertools::{EitherOrBoth, Itertools};
use std::{cmp, collections::BTreeMap, iter};

// Map of forks created by a single peer that are in the ancestry of an event.
pub(super) type ForkMap = BTreeMap<usize, IndexSet>;

// Immutable set of integer indices
#[derive(Clone)]
pub(crate) struct IndexSet(Vec<usize>);

impl IndexSet {
    pub fn new(index: usize) -> Self {
        IndexSet(vec![index])
    }

    pub fn union(&self, other: &Self) -> Self {
        IndexSet(
            self.0
                .iter()
                .merge(other.0.iter())
                .dedup()
                .cloned()
                .collect(),
        )
    }

    pub fn insert(&self, index: usize) -> Self {
        IndexSet(
            self.0
                .iter()
                .cloned()
                .merge(iter::once(index))
                .dedup()
                .collect(),
        )
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn contains(&self, index: usize) -> bool {
        self.0.binary_search(&index).is_ok()
    }

    pub fn intersects(&self, other: &Self) -> bool {
        self.0
            .iter()
            .merge_join_by(other.0.iter(), |x, y| x.cmp(y))
            .any(|either| match either {
                EitherOrBoth::Both(..) => true,
                _ => false,
            })
    }
}

// Information about ancestor events.
#[derive(Clone)]
pub(super) struct AncestorInfo {
    // index-by-creator of the last event by the current peer that is ancestor of the current
    // event.
    pub last: usize,

    // Info about forks in the ancestry of the current event.
    // Key is the index-by-creator of the forked events, value is a list of indices of the fork
    // branches that the current event in on.
    pub forks: ForkMap,
}

impl AncestorInfo {
    pub fn new() -> Self {
        Self {
            last: 0,
            forks: ForkMap::new(),
        }
    }
}

pub(super) fn compute_ancestor_info<S: SecretId>(
    creator: PeerIndex,
    index_by_creator: usize,
    self_parent: Option<&Event<S::PublicId>>,
    other_parent: Option<&Event<S::PublicId>>,
    peer_list: &PeerList<S>,
) -> PeerIndexMap<AncestorInfo> {
    let mut result = match (self_parent, other_parent) {
        (Some(self_parent), Some(other_parent)) => {
            merge_ancestor_info_maps(self_parent.ancestor_info(), other_parent.ancestor_info())
        }
        (Some(self_parent), None) => self_parent.ancestor_info().clone(),
        (None, Some(other_parent)) => other_parent.ancestor_info().clone(),
        (None, None) => PeerIndexMap::new(),
    };

    let info = result.entry(creator).or_insert_with(AncestorInfo::new);
    info.last = index_by_creator;

    let fork_index = peer_list.events_by_index(creator, index_by_creator).count();
    if fork_index > 0 {
        let _ = info
            .forks
            .insert(index_by_creator, IndexSet::new(fork_index));
    }

    result
}

fn merge_ancestor_info_maps(
    map0: &PeerIndexMap<AncestorInfo>,
    map1: &PeerIndexMap<AncestorInfo>,
) -> PeerIndexMap<AncestorInfo> {
    // Merge the two maps: if an entry exists in only one of the map, copy it over,
    // if it exists in both, merge them by calling `AncestorInfo::merge`.
    // We can use `merge_join_by` from `itertools` because `PeerIndexMap::iter` yields the entries
    // in lexicographically ascending order.
    map0.iter()
        .merge_join_by(map1.iter(), |(peer_index0, _), (peer_index1, _)| {
            peer_index0.cmp(peer_index1)
        })
        .map(|either| match either {
            EitherOrBoth::Left((peer_index, info)) | EitherOrBoth::Right((peer_index, info)) => {
                (peer_index, info.clone())
            }
            EitherOrBoth::Both((peer_index, info0), (_, info1)) => {
                (peer_index, merge_ancestor_infos(info0, info1))
            }
        })
        .collect()
}

fn merge_ancestor_infos(info0: &AncestorInfo, info1: &AncestorInfo) -> AncestorInfo {
    AncestorInfo {
        last: cmp::max(info0.last, info1.last),
        forks: merge_fork_maps(info0, info1),
    }
}

fn merge_fork_maps(info0: &AncestorInfo, info1: &AncestorInfo) -> ForkMap {
    info0
        .forks
        .iter()
        .merge_join_by(info1.forks.iter(), |(key0, _), (key1, _)| key0.cmp(key1))
        .map(|either| match either {
            EitherOrBoth::Left((&index_by_creator, fork_set)) => (
                index_by_creator,
                merge_with_implicit_fork_set(fork_set, index_by_creator, info1.last),
            ),
            EitherOrBoth::Right((&index_by_creator, fork_set)) => (
                index_by_creator,
                merge_with_implicit_fork_set(fork_set, index_by_creator, info0.last),
            ),
            EitherOrBoth::Both((&index_by_creator, fork_set0), (_, fork_set1)) => {
                (index_by_creator, fork_set0.union(fork_set1))
            }
        })
        .collect()
}

fn merge_with_implicit_fork_set(
    forks: &IndexSet,
    index_by_creator: usize,
    last_ancestor: usize,
) -> IndexSet {
    if last_ancestor >= index_by_creator {
        // The second event is ancestor of the first event of the fork. Merge the fork set of the
        // first event with the implicit fork set [0].
        forks.insert(0)
    } else {
        // The second event is not an ancestor of any event of the fork - just clone the first fork
        // set.
        forks.clone()
    }
}
