// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod membership_list;
mod peer;
mod peer_state;

pub(crate) use self::membership_list::MembershipListChange;
pub use self::peer_state::PeerState;
#[cfg(all(test, feature = "mock"))]
pub(crate) use self::snapshot::PeerListSnapshot;

#[cfg(feature = "malice-detection")]
use self::membership_list::MembershipListWithChanges;
use self::peer::Peer;
use error::Error;
#[cfg(any(test, feature = "testing"))]
use gossip::Graph;
use gossip::{Event, EventIndex, IndexedEventRef};
use hash::Hash;
use id::SecretId;
#[cfg(any(test, feature = "testing"))]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
use std::collections::btree_map::{self, BTreeMap, Entry};
#[cfg(any(test, feature = "testing", feature = "malice-detection"))]
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::iter;

pub(crate) struct PeerList<S: SecretId> {
    our_id: S,
    peers: BTreeMap<S::PublicId, Peer<S::PublicId>>,
}

impl<S: SecretId> PeerList<S> {
    pub fn new(our_id: S) -> Self {
        PeerList {
            our_id,
            peers: BTreeMap::new(),
        }
    }

    pub fn our_id(&self) -> &S {
        &self.our_id
    }

    pub fn our_pub_id(&self) -> &S::PublicId {
        self.our_id.public_id()
    }

    /// Returns all sorted peer_ids.
    pub fn all_ids(&self) -> impl Iterator<Item = &S::PublicId> {
        self.peers.keys()
    }

    /// Returns ids of all peers that can vote.
    pub fn voter_ids(&self) -> impl Iterator<Item = &S::PublicId> {
        self.voters().map(|(id, _)| id)
    }

    /// Returns an iterator of peers that we can send gossip to.
    pub fn gossip_recipient_ids(&self) -> impl Iterator<Item = &S::PublicId> {
        let ids = if self.our_state().can_send() {
            let ids = self
                .peers
                .iter()
                .filter(move |(id, peer)| {
                    *id != self.our_pub_id() && peer.state.can_vote() && peer.state.can_recv()
                })
                .map(|(id, _)| id);
            Some(ids)
        } else {
            None
        };

        ids.into_iter().flat_map(|ids| ids)
    }

    /// Returns an unsorted map of peer_id => Hash(peer_id).
    pub fn peer_id_hashes(&self) -> impl Iterator<Item = (&S::PublicId, &Hash)> {
        self.peers.iter().map(|(id, peer)| (id, peer.id_hash()))
    }

    /// Returns an iterator of peers.
    pub fn iter(&self) -> btree_map::Iter<S::PublicId, Peer<S::PublicId>> {
        self.peers.iter()
    }

    /// Returns an iterator of peers that can vote.
    pub fn voters(&self) -> impl Iterator<Item = (&S::PublicId, &Peer<S::PublicId>)> {
        self.peers.iter().filter(|(_, peer)| peer.state.can_vote())
    }

    pub fn has_peer(&self, peer_id: &S::PublicId) -> bool {
        self.peers.contains_key(peer_id)
    }

    pub fn peer_state(&self, peer_id: &S::PublicId) -> PeerState {
        self.peers
            .get(peer_id)
            .map(|peer| peer.state)
            .unwrap_or_else(PeerState::inactive)
    }

    pub fn our_state(&self) -> PeerState {
        self.peer_state(self.our_id.public_id())
    }

    /// Adds a peer in the given state into the map.
    pub fn add_peer(&mut self, peer_id: S::PublicId, state: PeerState) {
        let changed = match self.peers.entry(peer_id.clone()) {
            Entry::Occupied(entry) => {
                log_or_panic!(
                    "{:?} already has {:?} in the peer list",
                    self.our_id.public_id(),
                    entry.key()
                );
                false
            }
            Entry::Vacant(entry) => {
                let peer = Peer::new(entry.key(), state);
                let _ = entry.insert(peer);
                state.can_vote()
            }
        };

        if changed {
            if peer_id == *self.our_pub_id() {
                let other_peer_ids: Vec<_> = self.peers.keys().cloned().collect();
                for other_peer_id in other_peer_ids {
                    self.record_our_membership_list_change(MembershipListChange::Add(other_peer_id))
                }
            } else {
                self.record_our_membership_list_change(MembershipListChange::Add(peer_id))
            }
        }
    }

    pub fn remove_peer(&mut self, peer_id: &S::PublicId) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.state = PeerState::inactive();
        } else {
            debug!(
                "{:?} tried to remove unknown peer {:?}",
                self.our_id.public_id(),
                peer_id
            );
            return;
        }

        self.record_our_membership_list_change(MembershipListChange::Remove(peer_id.clone()))
    }

    pub fn change_peer_state(&mut self, peer_id: &S::PublicId, state: PeerState) {
        let changed = if let Some(peer) = self.peers.get_mut(peer_id) {
            let could_vote = peer.state.can_vote();
            peer.state |= state;
            peer.state.can_vote() && !could_vote
        } else {
            log_or_panic!(
                "{:?} tried to change state of unknown peer {:?}",
                self.our_id.public_id(),
                peer_id
            );
            false
        };

        if changed {
            self.record_our_membership_list_change(MembershipListChange::Add(peer_id.clone()))
        }
    }

    /// Add `other_peer_id` to `peer_id`'s membership list.
    /// If `peer_id` is ourselves, this function does nothing to prevent redundancy (the `PeerList`
    /// itself is already our membership list).
    pub fn add_to_peer_membership_list(
        &mut self,
        peer_id: &S::PublicId,
        other_peer_id: S::PublicId,
    ) {
        self.change_peer_membership_list(peer_id, MembershipListChange::Add(other_peer_id))
    }

    /// Remove `other_peer_id` from `peer_id`'s membership list.
    pub fn remove_from_peer_membership_list(
        &mut self,
        peer_id: &S::PublicId,
        other_peer_id: S::PublicId,
    ) {
        self.change_peer_membership_list(peer_id, MembershipListChange::Remove(other_peer_id))
    }

    pub fn change_peer_membership_list(
        &mut self,
        peer_id: &S::PublicId,
        change: MembershipListChange<S::PublicId>,
    ) {
        if *peer_id == *self.our_id.public_id() {
            return;
        }

        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.change_membership_list(change)
        } else {
            log_or_panic!(
                "{:?} tried to change membership list of unknown peer {:?}",
                self.our_id.public_id(),
                peer_id
            )
        }
    }

    /// Initialise the membership list of `peer_id`.
    pub fn initialise_peer_membership_list<I>(&mut self, peer_id: &S::PublicId, membership_list: I)
    where
        I: IntoIterator<Item = S::PublicId>,
    {
        // Do not populate our membership list as it would be redundant.
        if *peer_id == *self.our_id.public_id() {
            return;
        }

        if let Some(peer) = self.peers.get_mut(peer_id) {
            let changes = membership_list
                .into_iter()
                .chain(iter::once(peer_id.clone()))
                .map(MembershipListChange::Add);

            for change in changes {
                peer.change_membership_list(change)
            }
        } else {
            log_or_panic!(
                "{:?} tried to initialise membership list of unknown peer {:?}",
                self.our_id.public_id(),
                peer_id
            )
        }
    }

    /// Returns whether the membership list of the given peer is already initialised.
    pub fn is_peer_membership_list_initialised(&self, peer_id: &S::PublicId) -> bool {
        self.peers
            .get(peer_id)
            .map_or(false, |peer| !peer.membership_list().is_empty())
    }

    /// Same as `peer_membership_list_shapshot` except if there is a `Remove` at `event_index`,
    /// then that `Remove` won't be applied to the resulting list.
    #[cfg(feature = "malice-detection")]
    pub fn peer_membership_list_snapshot_excluding_last_remove(
        &self,
        peer_id: &S::PublicId,
        event_index: usize,
    ) -> Option<BTreeSet<S::PublicId>> {
        let (mut list, changes) = self.peer_membership_list_and_changes(peer_id)?;

        for (index, change) in changes.iter().rev() {
            if *index == event_index && !change.is_remove() {
                continue;
            }
            if *index < event_index {
                break;
            }
            let _ = change.unapply(&mut list);
        }

        Some(list)
    }

    /// Returns the history of changes to the membership list of the given peer.
    pub fn peer_membership_list_changes(
        &self,
        peer_id: &S::PublicId,
    ) -> &[(usize, MembershipListChange<S::PublicId>)] {
        if let Some(peer) = self.peers.get(peer_id) {
            peer.membership_list_changes()
        } else {
            &[]
        }
    }

    /// Returns the index of the last event created by this peer. Returns `None` if cannot find.
    pub fn last_event(&self, peer_id: &S::PublicId) -> Option<EventIndex> {
        self.peers
            .get(peer_id)
            .and_then(|peer| peer.events().rev().next())
    }

    /// Returns the indices of the events at the given index-by-creator.
    pub fn events_by_index<'a>(
        &'a self,
        peer_id: &S::PublicId,
        index: usize,
    ) -> impl Iterator<Item = EventIndex> + 'a {
        self.peers
            .get(peer_id)
            .into_iter()
            .flat_map(move |peer| peer.events_by_index(index))
    }

    /// Returns the index of the last event gossiped to us by the given peer.
    pub fn last_gossiped_event_by(&self, peer_id: &S::PublicId) -> Option<EventIndex> {
        self.peers
            .get(peer_id)
            .and_then(|peer| peer.last_gossiped_event)
    }

    /// Record that the given peer gossiped to us the given event.
    pub fn record_gossiped_event_by(&mut self, peer_id: &S::PublicId, event_index: EventIndex) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            if peer
                .last_gossiped_event
                .map(|current| current < event_index)
                .unwrap_or(false)
            {
                peer.last_gossiped_event = Some(event_index)
            }
        } else {
            log_or_panic!(
                "{:?} tried to record gossiped event by unknown peer {:?}",
                self.our_id.public_id(),
                peer_id
            )
        }
    }

    pub fn confirm_can_add_event<T: NetworkEvent>(
        &self,
        event: &Event<T, S::PublicId>,
    ) -> Result<(), Error> {
        if let Some(peer) = self.peers.get(event.creator()) {
            if *event.creator() == *self.our_id.public_id() || peer.state.can_send() {
                Ok(())
            } else {
                Err(Error::InvalidPeerState {
                    required: PeerState::SEND,
                    actual: peer.state,
                })
            }
        } else {
            Err(Error::UnknownPeer)
        }
    }

    /// Adds event created by the peer. Returns an error if the creator is not known, or if we
    /// already held an event from this peer with this index, but that event's hash is different to
    /// the one being added (in which case `peers` is left unmodified).
    pub fn add_event<T: NetworkEvent>(&mut self, event: IndexedEventRef<T, S::PublicId>) {
        if let Some(peer) = self.peers.get_mut(event.creator()) {
            peer.add_event(event.index_by_creator(), event.event_index())
        }
    }

    /// Removes last event from its creator.
    #[cfg(test)]
    pub fn remove_last_event(&mut self, creator: &S::PublicId) -> Option<EventIndex> {
        if let Some(peer) = self.peers.get_mut(creator) {
            peer.remove_last_event()
        } else {
            None
        }
    }

    /// Hashes of events of the given creator, in insertion order.
    pub fn peer_events<'a>(
        &'a self,
        peer_id: &S::PublicId,
    ) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.peers
            .get(peer_id)
            .into_iter()
            .flat_map(|peer| peer.events())
    }

    /// Hashes of our events in insertion order.
    #[cfg(any(test, feature = "malice-detection"))]
    pub fn our_events<'a>(&'a self) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.peer_events(self.our_id.public_id())
    }

    fn record_our_membership_list_change(&mut self, change: MembershipListChange<S::PublicId>) {
        if let Some(us) = self.peers.get_mut(self.our_id.public_id()) {
            us.record_membership_list_change(change)
        }
    }

    #[cfg(feature = "malice-detection")]
    fn peer_membership_list_and_changes(
        &self,
        peer_id: &S::PublicId,
    ) -> Option<MembershipListWithChanges<S::PublicId>> {
        let peer = self.peers.get(peer_id)?;
        let list = if peer_id == self.our_pub_id() {
            self.voter_ids().cloned().collect()
        } else {
            peer.membership_list().clone()
        };

        if list.is_empty() {
            None
        } else {
            Some((list, peer.membership_list_changes()))
        }
    }
}

impl<S: SecretId> Debug for PeerList<S> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        writeln!(
            formatter,
            "PeerList{{ our_id: {:?}",
            self.our_id.public_id()
        )?;
        for peer in &self.peers {
            writeln!(formatter, "    {:?},", peer)?;
        }
        write!(formatter, "}}")
    }
}

#[cfg(any(test, feature = "testing"))]
impl PeerList<PeerId> {
    // Creates a new PeerList using the input parameters directly.
    pub(super) fn new_from_dot_input(
        our_id: PeerId,
        graph: &Graph<Transaction, PeerId>,
        peer_data: BTreeMap<PeerId, (PeerState, BTreeSet<PeerId>)>,
    ) -> Self {
        let peers = peer_data
            .into_iter()
            .map(|(peer_id, (state, membership_list))| {
                let peer = Peer::new_from_dot_input(&peer_id, state, membership_list, graph);
                (peer_id, peer)
            }).collect();

        PeerList { our_id, peers }
    }
}

#[cfg(test)]
pub(crate) mod snapshot {
    use super::*;
    use gossip::EventHash;
    use id::PublicId;

    #[derive(Eq, PartialEq, Debug)]
    pub(crate) struct PeerListSnapshot<P: PublicId>(
        BTreeMap<P, (PeerState, BTreeSet<(usize, EventHash)>)>,
    );

    #[cfg(feature = "mock")]
    impl<P: PublicId> PeerListSnapshot<P> {
        pub fn new<T: NetworkEvent, S: SecretId<PublicId = P>>(
            peer_list: &PeerList<S>,
            graph: &Graph<T, P>,
        ) -> Self {
            PeerListSnapshot(
                peer_list
                    .iter()
                    .map(|(peer_id, peer)| {
                        let events = peer
                            .indexed_events()
                            .filter_map(|(index_by_creator, event_index)| {
                                graph
                                    .get(event_index)
                                    .map(|event| (index_by_creator, *event.hash()))
                            })
                            .collect();

                        (peer_id.clone(), (peer.state, events))
                    })
                    .collect(),
            )
        }
    }
}
