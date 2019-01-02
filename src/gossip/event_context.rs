// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::graph::Graph;
use crate::id::SecretId;
use crate::network_event::NetworkEvent;
use crate::observation::{ConsensusMode, ObservationStore};
use crate::peer_list::PeerList;

pub(crate) struct EventContextRef<'a, T: NetworkEvent, S: SecretId> {
    pub(crate) graph: &'a Graph<S::PublicId>,
    pub(crate) peer_list: &'a PeerList<S>,
    pub(crate) observations: &'a ObservationStore<T, S::PublicId>,
}

// `#[derive(Clone)]` doesn't work here for some reason...
impl<'a, T: NetworkEvent, S: SecretId> Clone for EventContextRef<'a, T, S> {
    fn clone(&self) -> Self {
        Self {
            graph: self.graph,
            peer_list: self.peer_list,
            observations: self.observations,
        }
    }
}

// ...neither does `#[derive(Copy)]`.
impl<'a, T: NetworkEvent, S: SecretId> Copy for EventContextRef<'a, T, S> {}

pub(crate) struct EventContextMut<'a, T: NetworkEvent, S: SecretId> {
    pub(crate) graph: &'a Graph<S::PublicId>,
    pub(crate) peer_list: &'a PeerList<S>,
    pub(crate) observations: &'a mut ObservationStore<T, S::PublicId>,
    pub(crate) consensus_mode: ConsensusMode,
}
