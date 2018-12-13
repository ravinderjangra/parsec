// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use peer_list::{PeerIndex, PeerIndexSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MembershipListChange {
    Add(PeerIndex),
    Remove(PeerIndex),
}

impl MembershipListChange {
    pub(super) fn apply(&self, peers: &mut PeerIndexSet) -> bool {
        match *self {
            MembershipListChange::Add(index) => peers.insert(index),
            MembershipListChange::Remove(index) => peers.remove(&index),
        }
    }

    #[cfg(feature = "malice-detection")]
    pub(super) fn unapply(&self, peers: &mut PeerIndexSet) -> bool {
        match *self {
            MembershipListChange::Add(index) => peers.remove(&index),
            MembershipListChange::Remove(index) => peers.insert(index),
        }
    }

    #[cfg(feature = "malice-detection")]
    pub(super) fn is_remove(&self) -> bool {
        match *self {
            MembershipListChange::Remove(_) => true,
            MembershipListChange::Add(_) => false,
        }
    }
}

#[cfg(feature = "malice-detection")]
pub(super) type MembershipListWithChanges<'a> = (PeerIndexSet, &'a [(usize, MembershipListChange)]);
