// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MembershipListChange<P> {
    Add(P),
    Remove(P),
}

impl<P: Clone + Ord> MembershipListChange<P> {
    pub(super) fn apply(&self, peers: &mut BTreeSet<P>) -> bool {
        match *self {
            MembershipListChange::Add(ref peer_id) => peers.insert(peer_id.clone()),
            MembershipListChange::Remove(ref peer_id) => peers.remove(peer_id),
        }
    }

    #[cfg(feature = "malice-detection")]
    pub(super) fn unapply(&self, peers: &mut BTreeSet<P>) -> bool {
        match *self {
            MembershipListChange::Add(ref peer_id) => peers.remove(peer_id),
            MembershipListChange::Remove(ref peer_id) => peers.insert(peer_id.clone()),
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
pub(super) type MembershipListWithChanges<'a, P> =
    (BTreeSet<P>, &'a [(usize, MembershipListChange<P>)]);
