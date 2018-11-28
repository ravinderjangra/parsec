// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::peer::{Peer, PeerStatus};
use super::schedule::{Schedule, ScheduleEvent, ScheduleOptions};
use super::Observation;
use block::Block;
use error::Error;
use gossip::{Request, Response};
use mock::{PeerId, Transaction};
use observation::{
    is_more_than_two_thirds, ConsensusMode, Malice, Observation as ParsecObservation,
};
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

enum Message {
    Request(Request<Transaction, PeerId>, usize),
    Response(Response<Transaction, PeerId>),
}

struct QueueEntry {
    pub sender: PeerId,
    pub message: Message,
    pub deliver_after: usize,
}

pub struct Network {
    pub peers: BTreeMap<PeerId, Peer>,
    genesis: BTreeSet<PeerId>,
    msg_queue: BTreeMap<PeerId, Vec<QueueEntry>>,
    consensus_mode: ConsensusMode,
}

#[derive(Debug)]
pub struct BlocksOrder {
    peer: PeerId,
    order: Vec<Observation>,
}

#[derive(Debug)]
pub enum ConsensusError {
    DifferingBlocksOrder {
        order_1: BlocksOrder,
        order_2: BlocksOrder,
    },
    WrongBlocksNumber {
        expected: usize,
        got: usize,
    },
    WrongPeers {
        expected: BTreeMap<PeerId, PeerStatus>,
        got: BTreeMap<PeerId, PeerStatus>,
    },
    InvalidSignatory {
        observation: Observation,
        signatory: PeerId,
    },
    TooFewSignatures {
        observation: Observation,
        signatures: BTreeSet<PeerId>,
    },
    UnexpectedAccusation {
        accuser: PeerId,
        accused: PeerId,
        malice: Malice<Transaction, PeerId>,
    },
}

impl Network {
    /// Create an empty test network
    pub fn new(consensus_mode: ConsensusMode) -> Self {
        Network {
            peers: BTreeMap::new(),
            genesis: BTreeSet::new(),
            msg_queue: BTreeMap::new(),
            consensus_mode,
        }
    }

    /// Create a test network with initial peers constructed from the given IDs
    pub fn with_peers<I: IntoIterator<Item = PeerId>>(
        all_ids: I,
        consensus_mode: ConsensusMode,
    ) -> Self {
        let genesis_group = all_ids.into_iter().collect::<BTreeSet<_>>();
        let peers = genesis_group
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    Peer::from_genesis(id.clone(), &genesis_group, consensus_mode),
                )
            }).collect();
        Network {
            genesis: genesis_group,
            peers,
            msg_queue: BTreeMap::new(),
            consensus_mode,
        }
    }

    pub fn consensus_mode(&self) -> ConsensusMode {
        self.consensus_mode
    }

    fn peers_with_status(&self, status: PeerStatus) -> impl Iterator<Item = &Peer> {
        self.peers
            .values()
            .filter(move |&peer| peer.status == status)
    }

    fn active_peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers_with_status(PeerStatus::Active)
    }

    fn present_peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values().filter(move |&peer| {
            peer.status == PeerStatus::Active || peer.status == PeerStatus::Pending
        })
    }

    /// Returns true if all peers hold the same sequence of stable blocks.
    fn blocks_all_in_sequence(&self) -> Result<(), ConsensusError> {
        let first_peer = unwrap!(self.active_peers().next());
        let payloads = first_peer.blocks_payloads();
        if let Some(peer) = self
            .active_peers()
            .find(|peer| peer.blocks_payloads() != payloads)
        {
            Err(ConsensusError::DifferingBlocksOrder {
                order_1: BlocksOrder {
                    peer: first_peer.id.clone(),
                    order: payloads.into_iter().cloned().collect(),
                },
                order_2: BlocksOrder {
                    peer: peer.id.clone(),
                    order: peer.blocks_payloads().into_iter().cloned().collect(),
                },
            })
        } else {
            Ok(())
        }
    }

    fn peer(&self, id: &PeerId) -> &Peer {
        unwrap!(self.peers.get(id))
    }

    fn peer_mut(&mut self, id: &PeerId) -> &mut Peer {
        unwrap!(self.peers.get_mut(id))
    }

    fn send_message(&mut self, src: PeerId, dst: &PeerId, message: Message, deliver_after: usize) {
        if self.peer(dst).status != PeerStatus::Active
            && self.peer(dst).status != PeerStatus::Pending
        {
            return;
        }
        self.msg_queue
            .entry(dst.clone())
            .or_insert_with(Vec::new)
            .push(QueueEntry {
                sender: src,
                message,
                deliver_after,
            });
    }

    /// Handles incoming requests and responses
    fn handle_messages(&mut self, peer: &PeerId, step: usize) {
        if let Some(msgs) = self.msg_queue.remove(peer) {
            let (to_handle, rest) = msgs
                .into_iter()
                .partition(|entry| entry.deliver_after <= step);
            let _ = self.msg_queue.insert(peer.clone(), rest);
            for entry in to_handle {
                match entry.message {
                    Message::Request(req, resp_delay) => match self
                        .peer_mut(peer)
                        .parsec
                        .handle_request(&entry.sender, req)
                    {
                        Ok(response) => {
                            self.send_message(
                                peer.clone(),
                                &entry.sender,
                                Message::Response(response),
                                step + resp_delay,
                            );
                        }
                        Err(Error::UnknownPeer) | Err(Error::InvalidPeerState { .. }) => (),
                        Err(e) => panic!("{:?}", e),
                    },
                    Message::Response(resp) => unwrap!(
                        self.peer_mut(peer)
                            .parsec
                            .handle_response(&entry.sender, resp)
                    ),
                }
            }
        }
    }

    fn check_consensus_broken(&self) -> Result<(), ConsensusError> {
        let mut block_order = BTreeMap::new();
        for peer in self.active_peers() {
            for (index, block) in peer.blocks().into_iter().enumerate() {
                let key = self.block_key(block);

                if let Some((old_peer, old_index)) = block_order.insert(key, (peer, index)) {
                    if old_index != index {
                        // old index exists and isn't equal to the new one
                        return Err(ConsensusError::DifferingBlocksOrder {
                            order_1: BlocksOrder {
                                peer: peer.id.clone(),
                                order: peer.blocks_payloads().into_iter().cloned().collect(),
                            },
                            order_2: BlocksOrder {
                                peer: old_peer.id.clone(),
                                order: old_peer.blocks_payloads().into_iter().cloned().collect(),
                            },
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn block_key<'a>(
        &self,
        block: &'a Block<Transaction, PeerId>,
    ) -> (&'a Observation, Option<&'a PeerId>) {
        let peer_id = if let ParsecObservation::OpaquePayload(_) = *block.payload() {
            if self.consensus_mode == ConsensusMode::Single {
                Some(&unwrap!(block.proofs().into_iter().next()).public_id)
            } else {
                None
            }
        } else {
            None
        };

        (block.payload(), peer_id)
    }

    fn consensus_complete(
        &self,
        expected_peers: &BTreeMap<PeerId, PeerStatus>,
        num_expected_observations: usize,
    ) -> bool {
        self.check_consensus(expected_peers, num_expected_observations)
            .is_ok()
    }

    /// Checks whether there is a right number of blocks and the blocks are in an agreeing order
    fn check_consensus(
        &self,
        expected_peers: &BTreeMap<PeerId, PeerStatus>,
        num_expected_observations: usize,
    ) -> Result<(), ConsensusError> {
        // Check the number of consensused blocks.
        let got = unwrap!(self.active_peers().next()).blocks_payloads().len();
        if num_expected_observations != got {
            return Err(ConsensusError::WrongBlocksNumber {
                expected: num_expected_observations,
                got,
            });
        }

        // Check peers.
        let got = self
            .peers
            .values()
            .map(|peer| (peer.id.clone(), peer.status))
            .collect();
        if *expected_peers != got {
            return Err(ConsensusError::WrongPeers {
                expected: expected_peers.clone(),
                got,
            });
        }

        // Check everybody has the same blocks in the same order.
        self.blocks_all_in_sequence()
    }

    fn check_block_signatories(
        &self,
        block: &Block<Transaction, PeerId>,
        section: &BTreeSet<PeerId>,
    ) -> Result<(), ConsensusError> {
        let signatories: BTreeSet<_> = block
            .proofs()
            .into_iter()
            .map(|proof| proof.public_id().clone())
            .collect();
        if let Some(pub_id) = signatories.difference(section).next() {
            return Err(ConsensusError::InvalidSignatory {
                observation: block.payload().clone(),
                signatory: pub_id.clone(),
            });
        }

        let consensus_mode = if let ParsecObservation::OpaquePayload(_) = *block.payload() {
            self.consensus_mode
        } else {
            ConsensusMode::Supermajority
        };
        let correct_signatories = match consensus_mode {
            ConsensusMode::Single => !signatories.is_empty(),
            ConsensusMode::Supermajority => {
                is_more_than_two_thirds(signatories.len(), section.len())
            }
        };
        if !correct_signatories {
            return Err(ConsensusError::TooFewSignatures {
                observation: block.payload().clone(),
                signatures: signatories,
            });
        }
        Ok(())
    }

    /// Checks if the blocks are only signed by valid voters
    fn check_blocks_signatories(&self) -> Result<(), ConsensusError> {
        let blocks = self.active_peers().next().unwrap().blocks();
        let mut valid_voters = BTreeSet::new();
        for block in blocks {
            match *block.payload() {
                ParsecObservation::Genesis(ref g) => {
                    // explicitly don't check signatories - the list of valid voters
                    // should be empty at this point
                    valid_voters = g.clone();
                }
                ParsecObservation::Add { ref peer_id, .. } => {
                    self.check_block_signatories(block, &valid_voters)?;
                    let _ = valid_voters.insert(peer_id.clone());
                }
                ParsecObservation::Remove { ref peer_id, .. } => {
                    self.check_block_signatories(block, &valid_voters)?;
                    let _ = valid_voters.remove(peer_id);
                }
                _ => {
                    self.check_block_signatories(block, &valid_voters)?;
                }
            }
        }
        Ok(())
    }

    /// Check that no node has been accused of malice.
    fn check_unexpected_accusations(&self, peer_id: &PeerId) -> Result<(), ConsensusError> {
        let peer = self.peer(peer_id);
        let accusation = peer
            .unpolled_accusations()
            .find(|(_, malice)| malice.is_provable());
        if let Some((offender, malice)) = accusation {
            return Err(ConsensusError::UnexpectedAccusation {
                accuser: peer.id.clone(),
                accused: offender.clone(),
                malice: malice.clone(),
            });
        } else {
            Ok(())
        }
    }

    /// Simulates the network according to the given schedule
    pub fn execute_schedule<R: Rng>(
        &mut self,
        rng: &mut R,
        schedule: Schedule,
        options: &ScheduleOptions,
    ) -> Result<(), ConsensusError> {
        let Schedule {
            peers,
            num_observations,
            events,
        } = schedule;
        let mut peer_removal_guard = PeerRemovalGuard::default();
        let mut pending_events: VecDeque<ScheduleEvent> = VecDeque::new();

        for event in events {
            while !pending_events.is_empty() {
                if let Some(pending_event) = pending_events.pop_front() {
                    if !self.execute_event(
                        rng,
                        options,
                        pending_event.clone(),
                        &mut peer_removal_guard,
                    )? {
                        pending_events.push_front(pending_event);
                        break;
                    }
                }
            }

            if !self.execute_event(rng, options, event.clone(), &mut peer_removal_guard)? {
                pending_events.push_back(event);
            }

            self.check_consensus_broken()?;
            if self.consensus_complete(&peers, num_observations) {
                break;
            }
        }

        self.check_consensus(&peers, num_observations)?;
        self.check_blocks_signatories()
    }

    // Returns 'Ok(true)' when event got executed, or 'Ok(false)' when the event needs to be delayed
    // due to the parsec membership status.
    fn execute_event<R: Rng>(
        &mut self,
        rng: &mut R,
        options: &ScheduleOptions,
        event: ScheduleEvent,
        peer_removal_guard: &mut PeerRemovalGuard,
    ) -> Result<bool, ConsensusError> {
        match event {
            ScheduleEvent::Genesis(genesis_group) => {
                let peers = genesis_group
                    .iter()
                    .map(|id| {
                        (
                            id.clone(),
                            Peer::from_genesis(id.clone(), &genesis_group, self.consensus_mode),
                        )
                    }).collect();
                for node in &genesis_group {
                    peer_removal_guard.record_new_voter(node.clone());
                }
                self.peers = peers;
                self.genesis = genesis_group;
                // do a full reset while we're at it
                self.msg_queue.clear();
            }
            ScheduleEvent::AddPeer(peer) => {
                let current_peers = self.active_peers().map(|peer| peer.id.clone()).collect();
                let _ = self.peers.insert(
                    peer.clone(),
                    Peer::from_existing(
                        peer.clone(),
                        &self.genesis,
                        &current_peers,
                        self.consensus_mode,
                    ),
                );
            }
            ScheduleEvent::RemovePeer(peer) => {
                if peer_removal_guard.attempt_to_remove_peer(&peer) {
                    (*self.peer_mut(&peer)).status = PeerStatus::Removed;
                } else {
                    return Ok(false);
                }
            }
            ScheduleEvent::Fail(peer) => {
                if peer_removal_guard.attempt_to_remove_peer(&peer) {
                    (*self.peer_mut(&peer)).status = PeerStatus::Failed;
                } else {
                    return Ok(false);
                }
            }
            ScheduleEvent::LocalStep(global_step) => {
                let present_peers: Vec<PeerId> =
                    self.present_peers().map(|peer| peer.id.clone()).collect();
                for peer in &present_peers {
                    self.peer_mut(&peer).make_votes();
                    self.handle_messages(&peer, global_step);
                    self.peer_mut(&peer).poll();
                    self.check_unexpected_accusations(&peer)?;

                    for block in self.peer(&peer).blocks_payloads() {
                        match block {
                            ParsecObservation::Remove { peer_id, .. } => {
                                peer_removal_guard.record_consensus_on_remove_peer(peer_id);
                            }
                            ParsecObservation::Add { peer_id, .. } => {
                                peer_removal_guard.record_new_voter(peer_id.clone());
                            }
                            _ => (),
                        }
                    }

                    if rng.gen::<f64>() < options.gossip_prob {
                        let mut recipient = peer;
                        while recipient == peer {
                            recipient = unwrap!(rng.choose(&present_peers));
                        }
                        let req_delay = options.gen_delay(rng);
                        let resp_delay = options.gen_delay(rng);

                        match self.peer(&peer).parsec.create_gossip(Some(&recipient)) {
                            Ok(request) => {
                                self.send_message(
                                    peer.clone(),
                                    &recipient,
                                    Message::Request(request, resp_delay),
                                    global_step + req_delay,
                                );
                            }
                            Err(e @ Error::InvalidPeerState { .. })
                            | Err(e @ Error::InvalidSelfState { .. }) => {
                                if self
                                    .peer(&peer)
                                    .parsec
                                    .gossip_recipients()
                                    .any(|peer_id| peer_id == recipient)
                                {
                                    panic!("Should be able to gossip {:?}", e);
                                }
                            }
                            Err(e) => panic!("{:?}", e),
                        }
                    }
                }
            }
            ScheduleEvent::VoteFor(peer, observation) => {
                if let ParsecObservation::Remove { ref peer_id, .. } = observation {
                    if !peer_removal_guard.attempt_to_remove_peer(&peer_id) {
                        return Ok(false);
                    }
                }

                self.peer_mut(&peer).vote_for(&observation);
            }
        }
        Ok(true)
    }
}

#[derive(Default)]
struct PeerRemovalGuard {
    voters: BTreeSet<PeerId>,
    nodes_to_be_removed: BTreeSet<PeerId>,
}

impl PeerRemovalGuard {
    fn record_new_voter(&mut self, voter: PeerId) {
        let _ = self.voters.insert(voter);
    }

    fn record_consensus_on_remove_peer(&mut self, peer: &PeerId) {
        let _ = self.nodes_to_be_removed.remove(peer);
        let _ = self.voters.remove(peer);
    }

    fn attempt_to_remove_peer(&mut self, peer: &PeerId) -> bool {
        if self.can_remove(peer) {
            let _ = self.nodes_to_be_removed.insert(peer.clone());
            true
        } else {
            false
        }
    }

    fn can_remove(&self, peer: &PeerId) -> bool {
        let active_participants = self.voters.len() - self.nodes_to_be_removed.len();
        is_more_than_two_thirds(active_participants, self.voters.len())
            || self.nodes_to_be_removed.contains(&peer)
    }
}
