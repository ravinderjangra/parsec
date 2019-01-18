// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::meta_vote::MetaVote;
use crate::gossip::IndexedEventRef;
use crate::id::PublicId;
use crate::observation::ObservationKey;
use crate::peer_list::{PeerIndex, PeerIndexMap, PeerIndexSet};

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct MetaEvent {
    pub observer: Observer,
    // Hashes of payloads of all the votes deemed interesting by this event.
    pub interesting_content: Vec<ObservationKey>,
    pub meta_votes: PeerIndexMap<Vec<MetaVote>>,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) enum Observer {
    // This event is observer (it has supermajority of observees and it is the first such event of
    // the same creator).
    This(PeerIndexSet),
    // This event isn't observer, but one of its self-ancestors is.
    Ancestor,
    // This event isn't observer and neither is any of its self-ancestors.
    None,
}

impl MetaEvent {
    pub fn build<P: PublicId>(event: IndexedEventRef<P>) -> MetaEventBuilder<P> {
        MetaEventBuilder {
            event,
            meta_event: MetaEvent {
                observer: Observer::None,
                interesting_content: Vec::new(),
                meta_votes: PeerIndexMap::default(),
            },
            new: true,
        }
    }

    pub fn rebuild<P: PublicId>(mut self, event: IndexedEventRef<P>) -> MetaEventBuilder<P> {
        self.meta_votes.clear();

        MetaEventBuilder {
            event,
            meta_event: self,
            new: false,
        }
    }

    pub fn is_observer(&self) -> bool {
        match self.observer {
            Observer::This(_) => true,
            _ => false,
        }
    }

    pub fn has_ancestor_observer(&self) -> bool {
        match self.observer {
            Observer::Ancestor => true,
            _ => false,
        }
    }
}

pub(crate) struct MetaEventBuilder<'a, P: PublicId + 'a> {
    event: IndexedEventRef<'a, P>,
    meta_event: MetaEvent,
    new: bool,
}

impl<'a, P: PublicId + 'a> MetaEventBuilder<'a, P> {
    pub fn event(&self) -> IndexedEventRef<'a, P> {
        self.event
    }

    pub fn is_new(&self) -> bool {
        self.new
    }

    pub fn is_observer(&self) -> bool {
        self.meta_event.is_observer()
    }

    pub fn has_observee(&self, peer_index: PeerIndex) -> bool {
        match self.meta_event.observer {
            Observer::This(ref observees) => observees.contains(peer_index),
            _ => false,
        }
    }

    pub fn set_observer(&mut self, observer: Observer) {
        self.meta_event.observer = observer;
    }

    pub fn set_interesting_content(&mut self, content: Vec<ObservationKey>) {
        self.meta_event.interesting_content = content;
    }

    pub fn add_meta_votes(&mut self, peer_index: PeerIndex, votes: Vec<MetaVote>) {
        let _ = self.meta_event.meta_votes.insert(peer_index, votes);
    }

    pub fn finish(self) -> MetaEvent {
        self.meta_event
    }
}

#[cfg(any(all(test, feature = "mock"), feature = "dump-graphs"))]
pub(crate) mod snapshot {
    use super::*;
    use crate::id::SecretId;
    use crate::observation::snapshot::ObservationKeySnapshot;
    use crate::peer_list::PeerList;
    use std::collections::{BTreeMap, BTreeSet};

    #[serde(bound = "")]
    #[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub(crate) struct MetaEventSnapshot<P: PublicId> {
        observees: BTreeSet<P>,
        interesting_content: Vec<ObservationKeySnapshot<P>>,
        meta_votes: BTreeMap<P, Vec<MetaVote>>,
    }

    impl<P: PublicId> MetaEventSnapshot<P> {
        pub fn new<S>(meta_event: &MetaEvent, peer_list: &PeerList<S>) -> Self
        where
            S: SecretId<PublicId = P>,
        {
            let observees = match meta_event.observer {
                Observer::This(ref observees) => observees
                    .iter()
                    .filter_map(|index| peer_list.get(index))
                    .map(|peer| peer.id().clone())
                    .collect(),
                _ => BTreeSet::new(),
            };

            Self {
                observees,
                interesting_content: meta_event
                    .interesting_content
                    .iter()
                    .filter_map(|key| ObservationKeySnapshot::new(key, peer_list))
                    .collect(),
                meta_votes: meta_event
                    .meta_votes
                    .iter()
                    .filter_map(|(peer_index, votes)| {
                        peer_list
                            .get(peer_index)
                            .map(|peer| (peer.id().clone(), votes.clone()))
                    })
                    .collect(),
            }
        }
    }

}
