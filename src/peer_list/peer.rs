// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::membership_list::MembershipListChange;
use super::peer_state::PeerState;
use gossip::EventIndex;
use hash::Hash;
use id::PublicId;
use serialise;
use std::collections::BTreeSet;
use std::iter;

#[derive(Debug)]
pub(crate) struct Peer<P: PublicId> {
    pub(super) id_hash: Hash,
    pub(super) state: PeerState,
    pub(super) events: Events,
    pub(super) last_gossiped_event: Option<EventIndex>,
    pub(super) membership_list: BTreeSet<P>,
    pub(super) membership_list_changes: Vec<(usize, MembershipListChange<P>)>,
}

impl<P: PublicId> Peer<P> {
    pub(super) fn new(id: &P, state: PeerState) -> Self {
        Self {
            id_hash: Hash::from(serialise(id).as_slice()),
            state,
            events: Events::new(),
            last_gossiped_event: None,
            membership_list: BTreeSet::new(),
            membership_list_changes: Vec::new(),
        }
    }

    pub fn state(&self) -> PeerState {
        self.state
    }

    pub fn events<'a>(&'a self) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.events.iter()
    }

    #[cfg(test)]
    pub fn indexed_events<'a>(
        &'a self,
    ) -> impl DoubleEndedIterator<Item = (usize, EventIndex)> + 'a {
        self.events.indexed()
    }

    pub fn events_by_index<'a>(&'a self, index: usize) -> impl Iterator<Item = EventIndex> + 'a {
        self.events.by_index(index)
    }

    pub(super) fn add_event(&mut self, index_by_creator: usize, event_index: EventIndex) {
        self.events.add(index_by_creator, event_index);
    }

    #[cfg(test)]
    pub(super) fn remove_last_event(&mut self) -> Option<EventIndex> {
        self.events.remove_last()
    }

    pub(super) fn change_membership_list(&mut self, change: MembershipListChange<P>) {
        if change.apply(&mut self.membership_list) {
            self.record_membership_list_change(change);
        }
    }

    pub(super) fn record_membership_list_change(&mut self, change: MembershipListChange<P>) {
        let index = self
            .events
            .indexed()
            .rev()
            .next()
            .map(|(index, _)| index)
            .unwrap_or(0);
        self.membership_list_changes.push((index, change));
    }

    pub(crate) fn membership_list(&self) -> &BTreeSet<P> {
        &self.membership_list
    }
}

#[derive(Debug)]
pub(super) struct Events(Vec<Slot>);

impl Events {
    pub fn new() -> Self {
        Events(Vec::new())
    }

    pub fn add(&mut self, index_by_creator: usize, event_index: EventIndex) {
        if let Some(slot) = self.0.get_mut(index_by_creator) {
            slot.add(event_index);
            return;
        }

        if index_by_creator != self.0.len() {
            log_or_panic!("Peer events must be added sequentially");
        }

        self.0.push(Slot::new(event_index))
    }

    #[cfg(test)]
    fn remove_last(&mut self) -> Option<EventIndex> {
        if let Some(slot) = self.0.last_mut() {
            if let Some(index) = slot.rest.pop() {
                return Some(index);
            }
        } else {
            return None;
        }

        self.0.pop().map(|slot| slot.first)
    }

    fn iter<'a>(&'a self) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.0.iter().flat_map(|slot| slot.iter())
    }

    fn indexed<'a>(&'a self) -> impl DoubleEndedIterator<Item = (usize, EventIndex)> + 'a {
        self.0
            .iter()
            .enumerate()
            .flat_map(|(index_by_creator, slot)| {
                slot.iter()
                    .map(move |event_index| (index_by_creator, event_index))
            })
    }

    fn by_index<'a>(&'a self, index_by_creator: usize) -> impl Iterator<Item = EventIndex> + 'a {
        self.0
            .get(index_by_creator)
            .into_iter()
            .flat_map(|slot| slot.iter())
    }
}

#[derive(Debug)]
struct Slot {
    first: EventIndex,
    rest: Vec<EventIndex>,
}

impl Slot {
    fn new(event_index: EventIndex) -> Self {
        Self {
            first: event_index,
            rest: Vec::new(),
        }
    }

    fn add(&mut self, event_index: EventIndex) {
        self.rest.push(event_index)
    }

    fn iter<'a>(&'a self) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        iter::once(self.first).chain(self.rest.iter().cloned())
    }
}
