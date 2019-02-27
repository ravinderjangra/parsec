// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Observation;
#[cfg(feature = "testing")]
use super::ParsedContents;
use crate::block::{Block, BlockGroup};
use crate::mock::{PeerId, Transaction};
use crate::observation::{
    is_more_than_two_thirds, ConsensusMode, Malice, Observation as ParsecObservation,
};
use crate::parsec::Parsec;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

/// This represents the peer's own view of its current status.
///
/// A new peer will start as `Pending` and transition to `Active` once `Peer::poll()` yields a block
/// adding itself to the network.  The peer can later be killed by setting the status to `Removed`
/// or `Failed`, although it is up to the test framework to handle this; the peer's `parsec` will
/// remain unaffected by the status change, so the tests should avoid calling or ignore peers which
/// are `Removed` or `Failed`.
///
/// Peer Start
///     |-> `Pending`
///     |
///     `Peer::poll()` yields a block
///         |-> `Active`
///         |
///         Need to kill peer
///             |-> `Removed`
///             |-> `Failed`
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum PeerStatus {
    Pending,
    Active,
    Removed,
    Failed,
}

/// This represents the network's view of a peer's state.
///
/// A new peer will start as `Joining`.  While in this state, its own status may or may not
/// transition from `PeerStatus::Pending` to `PeerStatus::Active`.  Once a supermajority of
/// currently `Joined` peers have reached consensus on this peer being added, its network view will
/// change to `Joined`.
///
/// While a peer is in the `Joining` state, it cannot be transitioned directly to the `Leaving`
/// state.  This means a peer must be seen by the network as having joined before it can be killed
/// or voted for removal.
///
/// Similarly, once a peer is set as `PeerStatus::Removed` or `PeerStatus::Failed`, or once a peer
/// votes to remove this one, the network view will change to `Leaving`.  Once a supermajority of
/// currently `Joined` peers have reached consensus on this peer being removed, the network view
/// will change to `Left`.
///
/// Peer start
///     |-> `Joining`
///     |
///     Supermajority of `Joined` peers see `Add` for this one
///         |-> `Joined`
///         |
///         Any peer votes to remove this one OR this peer is killed
///             |-> `Leaving`
///             |
///             Supermajority of `Joined` peers see `Remove` for this one
///                 |-> `Left`
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum NetworkView {
    Joining,
    Joined,
    Leaving,
    Left,
}

pub struct Peer {
    id: PeerId,
    pub parsec: Parsec<Transaction, PeerId>,
    /// The blocks returned by `parsec.poll()`, held in the order in which they were returned.
    grouped_blocks: Vec<BlockGroup<Transaction, PeerId>>,
    status: PeerStatus,
    network_view: NetworkView,
    votes_to_make: Vec<Observation>,
    /// Peers' IDs for which we have an `Observation::Add` block.
    added_peers_ids: BTreeSet<PeerId>,
    /// Peers' IDs for which we have an `Observation::Remove` block.
    removed_peers_ids: BTreeSet<PeerId>,
}

impl Peer {
    pub fn from_genesis(
        id: PeerId,
        genesis_group: &BTreeSet<PeerId>,
        consensus_mode: ConsensusMode,
    ) -> Self {
        Self {
            id: id.clone(),
            parsec: Parsec::from_genesis(id, genesis_group, consensus_mode),
            grouped_blocks: vec![],
            status: PeerStatus::Active,
            network_view: NetworkView::Joined,
            votes_to_make: vec![],
            added_peers_ids: BTreeSet::new(),
            removed_peers_ids: BTreeSet::new(),
        }
    }

    pub fn from_existing(
        id: PeerId,
        genesis_group: &BTreeSet<PeerId>,
        current_group: &BTreeSet<PeerId>,
        consensus_mode: ConsensusMode,
    ) -> Self {
        Self {
            id: id.clone(),
            parsec: Parsec::from_existing(id, genesis_group, current_group, consensus_mode),
            grouped_blocks: vec![],
            status: PeerStatus::Pending,
            network_view: NetworkView::Joining,
            votes_to_make: vec![],
            added_peers_ids: BTreeSet::new(),
            removed_peers_ids: BTreeSet::new(),
        }
    }

    #[cfg(feature = "testing")]
    pub(crate) fn from_parsed_contents(contents: ParsedContents) -> Self {
        let id = contents.our_id.clone();
        let parsec = Parsec::from_parsed_contents(contents);
        Self {
            id,
            parsec,
            grouped_blocks: vec![],
            status: PeerStatus::Active,
            network_view: NetworkView::Joined,
            votes_to_make: vec![],
            added_peers_ids: BTreeSet::new(),
            removed_peers_ids: BTreeSet::new(),
        }
    }

    pub fn vote_for(&mut self, observation: &Observation) {
        self.votes_to_make.push(observation.clone());
    }

    pub fn make_votes(&mut self) {
        let parsec = &mut self.parsec;
        self.votes_to_make
            .retain(|obs| !parsec.have_voted_for(obs) && parsec.vote_for(obs.clone()).is_err());
    }

    fn make_active_if_added(&mut self, block: &Block<Transaction, PeerId>) {
        if self.status == PeerStatus::Pending {
            if let ParsecObservation::Add { ref peer_id, .. } = *block.payload() {
                if self.id == *peer_id {
                    self.status = PeerStatus::Active;
                }
            }
        }
    }

    /// Repeatedly calls `parsec.poll()` until `None` and returns the index of the first new block.
    pub fn poll_all(&mut self) {
        while let Some(block_group) = self.parsec.poll() {
            for block in &block_group {
                self.make_active_if_added(block);
                match block.payload() {
                    ParsecObservation::Add { peer_id, .. } => {
                        assert!(self.added_peers_ids.insert(peer_id.clone()))
                    }
                    ParsecObservation::Remove { peer_id, .. } => {
                        assert!(self.removed_peers_ids.insert(peer_id.clone()))
                    }
                    _ => (),
                }
            }

            self.grouped_blocks.push(block_group);
        }
    }

    pub fn id(&self) -> &PeerId {
        &self.id
    }

    pub fn grouped_blocks(&self) -> &[BlockGroup<Transaction, PeerId>] {
        &self.grouped_blocks
    }

    pub fn blocks(&self) -> impl Iterator<Item = &Block<Transaction, PeerId>> {
        self.grouped_blocks.iter().flatten()
    }

    pub fn status(&self) -> PeerStatus {
        self.status
    }

    pub fn network_view(&self) -> NetworkView {
        self.network_view
    }

    pub fn is_running(&self) -> bool {
        match self.status {
            PeerStatus::Pending | PeerStatus::Active => true,
            PeerStatus::Removed | PeerStatus::Failed => false,
        }
    }

    /// Sets the node's own status to `Removed` and the network's view of it to `Leaving`.  Panics
    /// if the node in question isn't yet viewed by the network as being `Joined`.
    pub fn mark_as_removed(&mut self) {
        if self.status == PeerStatus::Failed {
            panic!("{:?} already has status Failed.", self.id);
        }
        self.mark_network_view_as_leaving();
        self.status = PeerStatus::Removed;
    }

    /// Sets the node's own status to `Failed` and the network's view of it to `Leaving`.  Panics if
    /// the node in question isn't yet viewed by the network as being `Joined`.
    pub fn mark_as_failed(&mut self) {
        if self.status == PeerStatus::Removed {
            panic!("{:?} already has status Removed.", self.id);
        }
        self.mark_network_view_as_leaving();
        self.status = PeerStatus::Failed;
    }

    /// Sets the network's view of the node to `Leaving` but doesn't affect the node's own status
    /// (e.g. other peers have voted for this one to be removed, but it is still unaware of this).
    /// Panics if the node in question isn't yet viewed by the network as being `Joined`.
    pub fn mark_network_view_as_leaving(&mut self) {
        match self.network_view {
            NetworkView::Joining => panic!("Network views {:?} as not yet having joined.", self.id),
            NetworkView::Joined => (),
            NetworkView::Leaving | NetworkView::Left => return,
        }
        self.network_view = NetworkView::Leaving;
    }

    /// Check if a supermajority of `Joined` peers have polled blocks changing the network view of
    /// `Joining` or `Leaving` peers.  Transition these to `Joined` or `Left` respectively.
    pub fn update_network_views(all_peers: &mut BTreeMap<PeerId, Peer>) {
        let mut added_counts = BTreeMap::new();
        let mut removed_counts = BTreeMap::new();
        let mut running_peers_count = 0;
        let do_count = |peer_ids: &BTreeSet<PeerId>, counts: &mut BTreeMap<PeerId, usize>| {
            for peer_id in peer_ids {
                let count = counts.entry(peer_id.clone()).or_insert(0);
                *count += 1;
            }
        };
        for peer in all_peers
            .values()
            .filter(|peer| peer.network_view == NetworkView::Joined)
        {
            do_count(&peer.added_peers_ids, &mut added_counts);
            do_count(&peer.removed_peers_ids, &mut removed_counts);
            running_peers_count += 1;
        }

        for (added_peer_id, count) in &added_counts {
            let peer = unwrap!(all_peers.get_mut(added_peer_id));
            if peer.network_view == NetworkView::Joining
                && is_more_than_two_thirds(*count, running_peers_count)
            {
                peer.network_view = NetworkView::Joined;
            }
        }

        for (removed_peer_id, count) in &removed_counts {
            if is_more_than_two_thirds(*count, running_peers_count) {
                unwrap!(all_peers.get_mut(removed_peer_id)).network_view = NetworkView::Left;
            }
        }
    }

    /// Returns the payloads of `self.blocks` in the order in which they were returned by `poll()`.
    pub fn blocks_payloads(&self) -> Vec<&Observation> {
        self.blocks().map(Block::payload).collect()
    }

    /// Returns an iterator over all accusations raised by this peer that haven't been retrieved by
    /// `poll_all()` yet.
    pub fn unpolled_accusations(
        &self,
    ) -> impl Iterator<Item = (&PeerId, &Malice<Transaction, PeerId>)> {
        self.parsec
            .our_unpolled_observations()
            .filter_map(|payload| match payload {
                ParsecObservation::Accusation {
                    ref offender,
                    ref malice,
                } => Some((offender, malice)),
                _ => None,
            })
    }

    pub fn is_active_and_has_block(&self, payload: &Observation) -> bool {
        self.status == PeerStatus::Active && self.blocks().any(|block| block.payload() == payload)
    }
}

impl Debug for Peer {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "{:?} [{:?}/{:?}]: Blocks: {:?}",
            self.id,
            self.status,
            self.network_view,
            self.blocks_payloads()
        )
    }
}
