// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    block::Block,
    dev_utils::{parse_test_dot_file, Record},
    error::Error,
    gossip::{Event, Graph, GraphSnapshot},
    id::{Proof, PublicId},
    meta_voting::MetaElectionSnapshot,
    mock::{self, PeerId, Transaction},
    observation::{ConsensusMode, Observation},
    parsec::TestParsec,
    peer_list::{PeerListSnapshot, PeerState},
};
use std::{collections::BTreeSet, fmt::Debug};

macro_rules! assert_matches {
    ($actual:expr, $expected:pat) => {
        match $actual {
            $expected => (),
            ref unexpected => panic!("{:?} does not match {}", unexpected, stringify!($expected)),
        }
    };
}

macro_rules! btree_set {
    ($($item:expr),*) => {{
        let mut set = BTreeSet::new();
        $(
            let _ = set.insert($item);
        )*
        set
    }}
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    peer_list: PeerListSnapshot<PeerId>,
    events: GraphSnapshot,
    meta_election: MetaElectionSnapshot<PeerId>,
    consensused_blocks: Vec<Block<Transaction, PeerId>>,
}

impl Snapshot {
    fn new(parsec: &TestParsec<Transaction, PeerId>) -> Self {
        Snapshot {
            peer_list: PeerListSnapshot::new(parsec.peer_list(), parsec.graph()),
            events: GraphSnapshot::new(parsec.graph()),
            meta_election: MetaElectionSnapshot::new(
                parsec.meta_election(),
                parsec.graph(),
                parsec.peer_list(),
            ),
            consensused_blocks: parsec.consensused_blocks().cloned().collect(),
        }
    }
}

fn nth_event<P: PublicId>(graph: &Graph<P>, n: usize) -> &Event<P> {
    unwrap!(graph.iter_from(n).next()).inner()
}

/// Testing related extensions to `Iterator`.
trait TestIterator: Iterator {
    /// Returns the only element in the iterator. Panics if the iterator yields less or more than
    /// one element.
    fn only(mut self) -> Self::Item
    where
        Self: Sized,
        Self::Item: Debug,
    {
        let item = unwrap!(self.next(), "Expected one element - got none.");
        assert!(
            self.by_ref().peekable().peek().is_none(),
            "Expected one element - got more (excess: {:?}).",
            self.collect::<Vec<_>>()
        );
        item
    }
}

impl<I: Iterator> TestIterator for I {}

#[test]
fn from_existing() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let peers = peers.into_iter().collect();

    let parsec = TestParsec::<Transaction, _>::from_existing(
        our_id.clone(),
        &peers,
        &peers,
        ConsensusMode::Supermajority,
    );

    // Existing section + us
    assert_eq!(parsec.peer_list().all_ids().count(), peers.len() + 1);

    // The gossip graph should be initially empty.
    assert_eq!(parsec.graph().len(), 0);
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Genesis group can't be empty")]
fn from_existing_requires_non_empty_genesis_group() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let peers = peers.into_iter().collect();

    let _ = TestParsec::<Transaction, _>::from_existing(
        our_id,
        &BTreeSet::new(),
        &peers,
        ConsensusMode::Supermajority,
    );
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Genesis group can't already contain us")]
fn from_existing_requires_that_genesis_group_does_not_contain_us() {
    let peers = mock::create_ids(10);
    let our_id = unwrap!(peers.first()).clone();
    let genesis_group = peers.iter().cloned().collect();
    let section = peers.into_iter().skip(1).collect();

    let _ = TestParsec::<Transaction, _>::from_existing(
        our_id,
        &genesis_group,
        &section,
        ConsensusMode::Supermajority,
    );
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Section can't be empty")]
fn from_existing_requires_non_empty_section() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let genesis_group = peers.into_iter().collect();

    let _ = TestParsec::<Transaction, _>::from_existing(
        our_id,
        &genesis_group,
        &BTreeSet::new(),
        ConsensusMode::Supermajority,
    );
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Section can't already contain us")]
fn from_existing_requires_that_section_does_not_contain_us() {
    let peers = mock::create_ids(10);
    let our_id = unwrap!(peers.first()).clone();
    let genesis_group = peers.iter().skip(1).cloned().collect();
    let section = peers.into_iter().collect();

    let _ = TestParsec::<Transaction, _>::from_existing(
        our_id,
        &genesis_group,
        &section,
        ConsensusMode::Supermajority,
    );
}

#[test]
fn from_genesis() {
    let peers = mock::create_ids(10);
    let our_id = unwrap!(peers.first()).clone();
    let peers = peers.into_iter().collect();

    let parsec = TestParsec::<Transaction, _>::from_genesis(
        our_id.clone(),
        &peers,
        ConsensusMode::Supermajority,
    );
    // the peer_list should contain the entire genesis group
    assert_eq!(parsec.peer_list().all_ids().count(), peers.len());
    // initial event + genesis_observation
    assert_eq!(parsec.graph().len(), 2);
    let initial_event = nth_event(parsec.graph(), 0);
    assert_eq!(*parsec.event_creator_id(&initial_event), our_id);
    assert!(initial_event.is_initial());
    let genesis_observation = nth_event(parsec.graph(), 1);
    assert_eq!(*parsec.event_creator_id(&genesis_observation), our_id);
    match parsec.event_payload(&genesis_observation) {
        Some(payload) => {
            assert_eq!(*payload, Observation::Genesis(peers));
        }
        None => panic!("Expected observation, but event carried no vote"),
    }
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Genesis group must contain us")]
fn from_genesis_requires_the_genesis_group_contains_us() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let peers = peers.into_iter().collect();

    let _ = TestParsec::<Transaction, _>::from_genesis(
        our_id.clone(),
        &peers,
        ConsensusMode::Supermajority,
    );
}

#[test]
fn from_parsed_contents() {
    let input_file = "0.dot";
    let parsed_contents = parse_test_dot_file(input_file);
    let parsed_contents_comparison = parse_test_dot_file(input_file);
    let parsec = TestParsec::from_parsed_contents(parsed_contents);
    assert_eq!(parsed_contents_comparison.graph, *parsec.graph());
    assert_eq!(
        parsed_contents_comparison.meta_election,
        *parsec.meta_election()
    );

    let parsed_contents_other = parse_test_dot_file("1.dot");
    assert_ne!(parsed_contents_other.graph, *parsec.graph());
    assert_ne!(parsed_contents_other.meta_election, *parsec.meta_election());
}

#[test]
fn add_peer() {
    // Generated with RNG seed: [411278735, 3293288956, 208850454, 2872654992].
    let mut parsed_contents = parse_test_dot_file("alice.dot");

    // The final decision to add Fred is reached in E_25, so pop this event for now.
    let e_25 = unwrap!(parsed_contents.remove_last_event());

    let mut alice = TestParsec::from_parsed_contents(parsed_contents);
    let genesis_group: BTreeSet<_> = alice
        .peer_list()
        .all_ids()
        .map(|(_, id)| id.clone())
        .collect();

    let alice_id = PeerId::new("Alice");
    let fred_id = PeerId::new("Fred");

    assert!(!alice
        .peer_list()
        .all_ids()
        .any(|(_, peer_id)| *peer_id == fred_id));

    let alice_snapshot = Snapshot::new(&alice);

    // Try calling `create_gossip()` for a peer which doesn't exist yet.
    assert_matches!(alice.create_gossip(&fred_id), Err(Error::UnknownPeer));
    assert_eq!(alice_snapshot, Snapshot::new(&alice));

    // Now add E_25, which should result in Alice adding Fred.
    let _e_25_index = unwrap!(alice.add_event(e_25));
    assert!(alice
        .peer_list()
        .all_ids()
        .any(|(_, peer_id)| *peer_id == fred_id));

    // Construct Fred's Parsec instance.
    let mut fred = TestParsec::from_existing(
        fred_id.clone(),
        &genesis_group,
        &genesis_group,
        ConsensusMode::Supermajority,
    );

    // Now pass a valid initial request from Alice to Fred.  The generated response would
    // normally only contain Fred's initial event, and the one recording receipt of Alice's
    // request.  However this graph doesn't represent the state it would be in if Alice were
    // actually sending such a request - it should have an event by Alice as the latest.  We
    // really only need to check here though that Fred doesn't respond with the full graph.
    let message = unwrap!(alice.create_gossip(&fred_id));
    let response = unwrap!(fred.handle_request(&alice_id, message));
    assert!(response.packed_events.len() < fred.graph().len());
}

#[test]
fn remove_peer() {
    // Generated with RNG seed: [1048220270, 1673192006, 3171321266, 2580820785].
    let mut parsed_contents = parse_test_dot_file("alice.dot");

    // The final decision to remove Eric is reached in the last event of Alice.
    let a_last = unwrap!(parsed_contents.remove_last_event());

    let mut alice = TestParsec::from_parsed_contents(parsed_contents);

    let eric_id = PeerId::new("Eric");
    let eric_index = unwrap!(alice.peer_list().get_index(&eric_id));

    assert!(alice
        .peer_list()
        .all_ids()
        .any(|(_, peer_id)| *peer_id == eric_id));
    assert_ne!(
        alice.peer_list().peer_state(eric_index),
        PeerState::inactive()
    );

    // Add event now which shall result in Alice removing Eric.
    unwrap!(alice.add_event(a_last));
    assert_eq!(
        alice.peer_list().peer_state(eric_index),
        PeerState::inactive()
    );

    // Try calling `create_gossip()` for Eric shall result in error.
    assert_matches!(
        alice.create_gossip(&eric_id),
        Err(Error::InvalidPeerState { .. })
    );

    // Construct Eric's parsec instance.
    let mut section: BTreeSet<_> = alice
        .peer_list()
        .all_ids()
        .map(|(_, id)| id.clone())
        .collect();
    let _ = section.remove(&eric_id);
    let mut eric = TestParsec::<Transaction, _>::from_existing(
        eric_id.clone(),
        &section,
        &section,
        ConsensusMode::Supermajority,
    );

    // Peer state is (VOTE | SEND) when created from existing. Need to update the states to
    // (VOTE | SEND | RECV).
    for peer_id in &section {
        eric.change_peer_state(peer_id, PeerState::RECV);
    }

    // Eric can no longer gossip to anyone.
    assert_matches!(
        eric.create_gossip(&PeerId::new("Alice")),
        Err(Error::InvalidSelfState { .. })
    );
}

#[test]
fn unpolled_and_unconsensused_observations() {
    // Generated with RNG seed: [3016139397, 1416620722, 2110786801, 3768414447], but using
    // Alice-002.dot to get the dot file where we get consensus on `Add(Eric)`.
    let mut alice_contents = parse_test_dot_file("alice.dot");
    let a_17 = unwrap!(alice_contents.remove_last_event());

    let mut alice = TestParsec::from_parsed_contents(alice_contents);

    // `Add(Eric)` should still be unconsensused since A_17 would be the first gossip event to
    // reach consensus on `Add(Eric)`, but it was removed from the graph.
    assert!(alice.has_unconsensused_observations());

    // Since we haven't called `poll()` yet, our vote for `Add(Eric)` should be returned by
    // `our_unpolled_observations()`.
    let add_eric = Observation::Add {
        peer_id: PeerId::new("Eric"),
        related_info: vec![],
    };
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

    // Call `poll()` and retry - should have no effect to unconsensused and unpolled
    // observations.
    assert!(alice.poll().is_none());
    assert!(alice.has_unconsensused_observations());
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

    // Have Alice process A_17 to get consensus on `Add(Eric)`.
    unwrap!(alice.add_event(a_17));

    // Since we haven't call `poll()` again yet, should still return our vote for `Add(Eric)`.
    // However, `has_unconsensused_observations()` should now return false.
    assert!(!alice.has_unconsensused_observations());
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

    // Call `poll()` and retry - should return none.
    unwrap!(alice.poll());
    assert!(alice.poll().is_none());
    assert!(alice.our_unpolled_observations().next().is_none());

    // Vote for a new observation and check it is returned as unpolled, and that
    // `has_unconsensused_observations()` returns false again.
    let vote = Observation::OpaquePayload(Transaction::new("ABCD"));
    unwrap!(alice.vote_for(vote.clone()));

    assert!(alice.has_unconsensused_observations());
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), vote);

    // Reset, and re-run, this time adding Alice's vote early to check that it is returned in
    // the correct order, i.e. after `Add(Eric)` at the point where `Add(Eric)` is consensused
    // but has not been returned by `poll()`.
    alice = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
    unwrap!(alice.vote_for(vote.clone()));
    let mut unpolled_observations = alice.our_unpolled_observations();
    assert_eq!(*unwrap!(unpolled_observations.next()), add_eric);
    assert_eq!(*unwrap!(unpolled_observations.next()), vote);
    assert!(unpolled_observations.next().is_none());
}

#[test]
fn our_unpolled_observations_with_consensus_mode_single() {
    let mut alice = Record::from(parse_test_dot_file("alice.dot")).play();

    let block = alice.poll().into_iter().flatten().only();
    assert_matches!(*block.payload(), Observation::Genesis(_));

    let block = alice.poll().into_iter().flatten().only();
    assert_matches!(*block.payload(), Observation::OpaquePayload(_));
    assert_eq!(
        block.proofs().iter().map(Proof::public_id).only(),
        alice.our_pub_id()
    );

    // Bob's vote is still in, but should not be returned here, as it's not "ours" (from Alice's
    // point of view).
    assert_eq!(alice.our_unpolled_observations().next(), None);
}

#[test]
fn gossip_after_fork() {
    let alice_id = PeerId::new("Alice");
    let bob_id = PeerId::new("Bob");

    let genesis_group = btree_set![
        alice_id.clone(),
        bob_id.clone(),
        PeerId::new("Carol"),
        PeerId::new("Dave")
    ];

    let mut alice = TestParsec::from_genesis(
        alice_id.clone(),
        &genesis_group,
        ConsensusMode::Supermajority,
    );

    // Alice creates couple of valid events.
    let a_1_index = unwrap!(alice.peer_list().our_events().next());
    let a_1_hash = *unwrap!(alice.graph().get(a_1_index)).hash();

    let a_2 = unwrap!(alice.new_event_from_observation(
        a_1_index,
        Observation::OpaquePayload(Transaction::new("one")),
    ));
    let a_2_hash = *a_2.hash();
    let a_2_index = unwrap!(alice.add_event(a_2));

    let a_3 = unwrap!(alice.new_event_from_observation(
        a_2_index,
        Observation::OpaquePayload(Transaction::new("two")),
    ));
    let a_3_hash = *a_3.hash();
    let a_3_packed = alice.pack_event(&a_3);
    unwrap!(alice.unpack_and_add_event(a_3_packed));

    let mut bob =
        TestParsec::from_genesis(bob_id.clone(), &genesis_group, ConsensusMode::Supermajority);

    // Alice sends a gossip request to Bob and receives a response back.
    let req = unwrap!(alice.create_gossip(&bob_id));
    let res = unwrap!(bob.handle_request(&alice_id, req));
    unwrap!(alice.handle_response(&bob_id, res));

    // Now Bob has a_0, a_1, a_2 and a_3 and Alice knows it.
    assert!(bob.graph().contains(&a_1_hash));
    assert!(bob.graph().contains(&a_2_hash));
    assert!(bob.graph().contains(&a_3_hash));

    // Alice creates a fork.
    let a_2_fork = unwrap!(alice.new_event_from_observation(
        a_1_index,
        Observation::OpaquePayload(Transaction::new("two-fork")),
    ));
    let a_2_fork_hash = *a_2_fork.hash();
    unwrap!(alice.add_event(a_2_fork));

    // Alice sends another gossip request to Bob.
    let req = unwrap!(alice.create_gossip(&bob_id));
    let _ = unwrap!(bob.handle_request(&alice_id, req));

    // Verify that Bob now has the forked event.
    assert!(bob.graph().contains(&a_2_fork_hash));
}

#[test]
fn sees() {
    // This graph contains fork.
    let record = Record::from(parse_test_dot_file("alice.dot"));
    let alice = TestParsec::from(record.play());

    let a2 = unwrap!(alice.graph().find_by_short_name("A_2"));
    let a3 = unwrap!(alice.graph().find_by_short_name("A_3"));
    let b2 = unwrap!(alice.graph().find_by_short_name("B_2"));
    let c1 = unwrap!(alice.graph().find_by_short_name("C_1"));
    let c2_0 = unwrap!(alice.graph().find_by_short_name("C_2,0"));
    let c2_1 = unwrap!(alice.graph().find_by_short_name("C_2,1"));

    // Simple no fork cases:
    assert!(a3.sees(a3));
    assert!(a3.sees(a2));
    assert!(a3.sees(b2));

    // A2 cannot prove the fork because it has only the first side of it in its ancestry.
    assert!(a2.sees(c1));
    assert!(a2.sees(c2_0));
    assert!(!a2.sees(c2_1));

    // Similarly, B2 has only the second side of the fork in its ancestry and so cannot prove it
    // either.
    assert!(b2.sees(c1));
    assert!(!b2.sees(c2_0));
    assert!(b2.sees(c2_1));

    // A3, on the other hand, has both sides of the fork in its ancestry and so can prove it.
    assert!(!a3.sees(c1));
    assert!(!a3.sees(c2_0));
    assert!(!a3.sees(c2_1));
}

#[cfg(feature = "malice-detection")]
mod handle_malice {
    use super::*;
    use crate::{
        dev_utils::{parse_dot_file_with_test_name, parse_test_dot_file, ParsedContents},
        gossip::{Event, EventContext, EventHash},
        id::SecretId,
        mock::Transaction,
        network_event::NetworkEvent,
        observation::Malice,
        peer_list::{PeerIndex, PeerList, PeerState},
        Request,
    };
    use std::ops::Deref;

    // Returns iterator over all votes cast by the given node.
    fn our_votes<T: NetworkEvent, S: SecretId>(
        parsec: &TestParsec<T, S>,
    ) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        parsec
            .peer_list()
            .our_events()
            .filter_map(move |index| parsec.graph().get(index))
            .filter_map(move |event| parsec.event_payload(event.inner()))
    }

    // Add the peers to the `PeerList` as the genesis group.
    fn add_genesis_group<S: SecretId>(
        peer_list: &mut PeerList<S>,
        genesis: &BTreeSet<S::PublicId>,
    ) {
        for peer_id in genesis {
            if let Some(index) = peer_list.get_index(peer_id) {
                peer_list.change_peer_state(index, PeerState::active())
            } else {
                let _ = peer_list.add_peer(peer_id.clone(), PeerState::active());
            }
        }
    }

    #[test]
    fn genesis_event_not_after_initial() {
        // Generated with RNG seed: [926181213, 2524489310, 392196615, 406869071].
        let alice_contents = parse_test_dot_file("alice.dot");
        let alice_id = alice_contents.peer_list.our_id().clone();
        let genesis: BTreeSet<_> = alice_contents
            .peer_list
            .all_ids()
            .map(|(_, id)| id.clone())
            .collect();
        let mut alice = TestParsec::from_parsed_contents(alice_contents);

        // Simulate Dave creating unexpected genesis.
        let dave_id = PeerId::new("Dave");
        let mut dave_contents = ParsedContents::new(dave_id.clone());

        dave_contents
            .peer_list
            .change_peer_state(PeerIndex::OUR, PeerState::active());
        add_genesis_group(&mut dave_contents.peer_list, &genesis);

        let d_0 = Event::new_initial(dave_contents.event_context());
        let d_0_index = dave_contents.add_event(d_0);

        let d_1 = unwrap!(dave_contents.new_event_from_observation(
            d_0_index,
            Observation::OpaquePayload(Transaction::new("dave's malicious vote")),
        ));
        let d_1_index = dave_contents.add_event(d_1);

        let d_2 = unwrap!(
            dave_contents.new_event_from_observation(d_1_index, Observation::Genesis(genesis),)
        );
        let d_2_hash = *d_2.hash();
        let _ = dave_contents.add_event(d_2);

        let mut dave = TestParsec::from_parsed_contents(dave_contents);

        // Dave sends malicious gossip to Alice.
        let request = unwrap!(dave.create_gossip(&alice_id));
        unwrap!(alice.handle_request(&dave_id, request));

        // Verify that Alice detected the malice and accused Dave.
        let (offender, hash) = unwrap!(our_votes(&alice)
            .filter_map(|payload| match *payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::UnexpectedGenesis(hash),
                } => Some((offender.clone(), hash)),
                _ => None,
            })
            .next());

        assert_eq!(offender, dave_id);
        assert_eq!(hash, d_2_hash);
    }

    #[test]
    fn genesis_event_creator_not_genesis_member() {
        // Generated with RNG seed: [848911612, 2362592349, 3178199135, 2458552022].
        let alice_contents = parse_test_dot_file("alice.dot");
        let alice_id = alice_contents.peer_list.our_id().clone();
        let genesis: BTreeSet<_> = alice_contents
            .peer_list
            .all_ids()
            .map(|(_, id)| id.clone())
            .collect();

        let mut alice = TestParsec::from_parsed_contents(alice_contents);

        // This is needed so the AddPeer(Eric) is consensused.
        unwrap!(alice.restart_consensus());

        // Simulate Eric creating unexpected genesis.
        let eric_id = PeerId::new("Eric");
        let mut eric_contents = ParsedContents::new(eric_id.clone());

        eric_contents
            .peer_list
            .change_peer_state(PeerIndex::OUR, PeerState::active());
        add_genesis_group(&mut eric_contents.peer_list, &genesis);

        let e_0 = Event::new_initial(eric_contents.event_context());
        let e_0_index = eric_contents.add_event(e_0);

        let e_1 = unwrap!(
            eric_contents.new_event_from_observation(e_0_index, Observation::Genesis(genesis),)
        );
        let e_1_hash = *e_1.hash();
        let _ = eric_contents.add_event(e_1);

        let mut eric = TestParsec::from_parsed_contents(eric_contents);

        // Eric sends malicious gossip to Alice.
        let request = unwrap!(eric.create_gossip(&alice_id));
        unwrap!(alice.handle_request(&eric_id, request));

        // Verify that Alice detected the malice and accused Eric.
        let (offender, hash) = unwrap!(our_votes(&alice)
            .filter_map(|payload| match *payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::UnexpectedGenesis(hash),
                } => Some((offender.clone(), hash)),
                _ => None,
            })
            .next());

        assert_eq!(offender, eric_id);
        assert_eq!(hash, e_1_hash);
    }

    fn initialise_parsed_contents(
        id: PeerId,
        genesis: &BTreeSet<PeerId>,
        second_event: Option<Observation<Transaction, PeerId>>,
    ) -> ParsedContents {
        let mut result = ParsedContents::new(id);
        add_genesis_group(&mut result.peer_list, genesis);

        let ev_0 = Event::new_initial(result.event_context());
        let ev_0_index = result.add_event(ev_0);
        let ev_1 = if let Some(obs_1) = second_event {
            unwrap!(result.new_event_from_observation(ev_0_index, obs_1,))
        } else {
            unwrap!(result
                .new_event_from_observation(ev_0_index, Observation::Genesis(genesis.clone()),))
        };

        let _ = result.add_event(ev_1);
        result
    }

    fn initialise_parsec(
        id: PeerId,
        genesis: &BTreeSet<PeerId>,
        second_event: Option<Observation<Transaction, PeerId>>,
    ) -> TestParsec<Transaction, PeerId> {
        let contents = initialise_parsed_contents(id, genesis, second_event);
        TestParsec::from_parsed_contents(contents)
    }

    #[test]
    fn missing_genesis_event() {
        let alice_id = PeerId::new("Alice");
        let dave_id = PeerId::new("Dave");

        let genesis = btree_set![alice_id.clone(), dave_id.clone()];

        // Create Alice where the first event is not a genesis event (malice)
        let mut alice = initialise_parsec(
            alice_id.clone(),
            &genesis,
            Some(Observation::OpaquePayload(Transaction::new("Foo"))),
        );
        let a_0_hash = *nth_event(alice.graph(), 0).hash();
        let a_1_hash = *nth_event(alice.graph(), 1).hash();

        // Create Dave where the first event is a genesis event containing both Alice and Dave.
        let mut dave = initialise_parsec(dave_id.clone(), &genesis, None);
        assert!(!dave.graph().contains(&a_0_hash));
        assert!(!dave.graph().contains(&a_1_hash));

        // Send gossip from Alice to Dave.
        let message = unwrap!(alice.create_gossip(&dave_id));
        unwrap!(dave.handle_request(&alice_id, message));
        assert!(dave.graph().contains(&a_0_hash));
        assert!(dave.graph().contains(&a_1_hash));

        // Verify that Dave detected and accused Alice for malice.
        let (offender, hash) = unwrap!(our_votes(&dave)
            .filter_map(|payload| match payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::MissingGenesis(hash),
                } => Some((offender, hash)),
                _ => None,
            })
            .next());
        assert_eq!(*offender, alice_id);
        assert_eq!(*hash, a_1_hash);
    }

    #[test]
    fn incorrect_genesis_event() {
        let alice_id = PeerId::new("Alice");
        let dave_id = PeerId::new("Dave");

        let genesis = btree_set![alice_id.clone(), dave_id.clone()];
        let false_genesis = btree_set![alice_id.clone(), PeerId::new("Derp")];

        // Create Alice where the first event is an incorrect genesis event (malice)
        let mut alice = initialise_parsec(
            alice_id.clone(),
            &genesis,
            Some(Observation::Genesis(false_genesis)),
        );
        let a_0_hash = *nth_event(alice.graph(), 0).hash();
        let a_1_hash = *nth_event(alice.graph(), 1).hash();

        // Create Dave where the first event is a genesis event containing both Alice and Dave.
        let mut dave = initialise_parsec(dave_id.clone(), &genesis, None);
        assert!(!dave.graph().contains(&a_0_hash));
        assert!(!dave.graph().contains(&a_1_hash));

        // Send gossip from Alice to Dave.
        let message = unwrap!(alice.create_gossip(&dave_id));
        // Alice's genesis should be rejected as invalid
        assert_matches!(
            dave.handle_request(&alice_id, message),
            Err(Error::InvalidEvent)
        );
        assert!(dave.graph().contains(&a_0_hash));
        // Dave's events shouldn't contain Alice's genesis because of the rejection
        assert!(!dave.graph().contains(&a_1_hash));

        // Verify that Dave detected and accused Alice for malice.
        let (offender, hash) = unwrap!(our_votes(&dave)
            .filter_map(|payload| match payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::IncorrectGenesis(hash),
                } => Some((offender, hash)),
                _ => None,
            })
            .next());
        assert_eq!(*offender, alice_id);
        assert_eq!(*hash, a_1_hash);
    }

    #[test]
    fn duplicate_votes() {
        // Generated with RNG seed: [1353978636, 426502568, 2862743769, 1583787884].
        //
        // Carol has already voted for "ABCD".  Create two new duplicate votes by Carol for this
        // opaque payload.
        let mut carol = TestParsec::from_parsed_contents(parse_test_dot_file("carol.dot"));

        let first_duplicate = unwrap!(carol.new_event_from_observation(
            carol.our_last_event_index(),
            Observation::OpaquePayload(Transaction::new("ABCD")),
        ));

        let first_duplicate_clone = unwrap!(carol.new_event_from_observation(
            carol.our_last_event_index(),
            Observation::OpaquePayload(Transaction::new("ABCD")),
        ));
        let first_duplicate_clone_packed = carol.pack_event(&first_duplicate_clone);

        let first_duplicate_hash = *first_duplicate.hash();
        let first_duplicate_index = unwrap!(carol.add_event(first_duplicate));
        let second_duplicate = unwrap!(carol.new_event_from_observation(
            first_duplicate_index,
            Observation::OpaquePayload(Transaction::new("ABCD")),
        ));
        let second_duplicate_packed = carol.pack_event(&second_duplicate);

        // Check that the first duplicate triggers an accusation by Alice, but that the
        // duplicate is still added to the graph.
        let mut alice = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        let carols_valid_vote_hash = *unwrap!(alice.graph().find_by_short_name("C_5")).hash();
        unwrap!(alice.unpack_and_add_event(first_duplicate_clone_packed));

        let carol_index = unwrap!(alice.peer_list().get_index(carol.our_pub_id()));
        let expected_accusations = vec![(
            carol_index,
            Malice::DuplicateVote(carols_valid_vote_hash, first_duplicate_hash),
        )];
        assert_eq!(*alice.pending_accusations(), expected_accusations);
        assert!(alice.graph().contains(&first_duplicate_hash));

        // Check that the second one doesn't trigger any further accusation, but is also added
        // to the graph.
        let second_duplicate_hash = *second_duplicate.hash();
        unwrap!(alice.unpack_and_add_event(second_duplicate_packed));
        assert_eq!(*alice.pending_accusations(), expected_accusations);
        assert!(alice.graph().contains(&second_duplicate_hash));
    }

    #[test]
    fn invalid_accusation() {
        // Generated with RNG seed: [935566334, 935694090, 88607029, 861330491].
        let mut alice_contents = parse_test_dot_file("alice.dot");

        let a_4_index = unwrap!(alice_contents.graph.find_by_short_name("A_4")).event_index();
        let d_1_hash = *unwrap!(alice_contents.graph.find_by_short_name("D_1")).hash();

        // Create an invalid accusation from Alice
        let a_5 = unwrap!(alice_contents.new_event_from_observation(
            a_4_index,
            Observation::Accusation {
                offender: PeerId::new("Dave"),
                malice: Malice::Fork(d_1_hash),
            },
        ));
        let a_5_hash = *a_5.hash();
        let _ = alice_contents.add_event(a_5);
        let mut alice = TestParsec::from_parsed_contents(alice_contents);
        assert!(alice.graph().contains(&a_5_hash));

        let mut carol = TestParsec::from_parsed_contents(parse_test_dot_file("carol.dot"));
        assert!(!carol.graph().contains(&a_5_hash));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(carol.our_pub_id()));

        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.graph().contains(&a_5_hash));

        // Verify that Carol detected malice and accused Alice of it.
        let (offender, hash) = unwrap!(our_votes(&carol)
            .filter_map(|payload| match payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::InvalidAccusation(hash),
                } => Some((offender, hash)),
                _ => None,
            })
            .next());
        assert_eq!(offender, alice.our_pub_id());
        assert_eq!(*hash, a_5_hash);
    }

    fn create_invalid_accusation() -> (EventHash, TestParsec<Transaction, PeerId>) {
        // Generated with RNG seed: [3932887254, 691979681, 2029125979, 3359276664]
        let mut alice_contents =
            parse_dot_file_with_test_name("alice.dot", "functional_tests_handle_malice_accomplice");

        let a_18_index = unwrap!(alice_contents.graph.find_by_short_name("A_18")).event_index();
        let d_1_hash = *unwrap!(alice_contents.graph.find_by_short_name("D_1")).hash();

        // Create an invalid accusation from Alice
        let a_19 = unwrap!(alice_contents.new_event_from_observation(
            a_18_index,
            Observation::Accusation {
                offender: PeerId::new("Dave"),
                malice: Malice::Fork(d_1_hash),
            },
        ));
        let a_19_hash = *a_19.hash();
        let _ = alice_contents.add_event(a_19);
        let alice = TestParsec::from_parsed_contents(alice_contents);
        assert!(alice.graph().contains(&a_19_hash));
        (a_19_hash, alice)
    }

    fn verify_accused_accomplice(
        accuser: &TestParsec<Transaction, PeerId>,
        suspect: &PeerId,
        event_hash: &EventHash,
        malice_hash: &EventHash,
    ) {
        let (offender, hash, against) = unwrap!(our_votes(accuser)
            .filter_map(|payload| match payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::Accomplice(hash, against),
                } => Some((offender, hash, against)),
                _ => None,
            })
            .next());
        assert_eq!(offender, suspect);
        assert_eq!(hash, event_hash);

        let against_hash = match against.deref() {
            Malice::InvalidAccusation(hash) => Some(hash),
            _ => None,
        }
        .expect("Not all malice types supported in test for now");
        assert_eq!(against_hash, malice_hash);
    }

    #[test]
    // Carol received gossip from Bob, which should have raised an accomplice accusation against
    // Alice but didn't.
    fn accomplice_basic() {
        let (invalid_accusation, mut alice) = create_invalid_accusation();

        let mut bob = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.graph().contains(&invalid_accusation));

        // Send gossip from Alice to Bob
        let message = unwrap!(alice.create_gossip(&PeerId::new("Bob")));
        unwrap!(bob.handle_request(alice.our_pub_id(), message));
        assert!(bob.graph().contains(&invalid_accusation));
        // Remove the invalid accusation event (B_20)
        unwrap!(bob.remove_last_event());

        let mut carol = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!carol.graph().contains(&invalid_accusation));

        // Send gossip from Bob to Carol, with the accusation event missing. Carol will see that
        // the accusation event is missing, and since Bob has now created a `Requesting` event is
        // sure that Bob didn't create the accusation he should have.
        let message = unwrap!(bob.create_gossip(&PeerId::new("Carol")));
        unwrap!(carol.handle_request(bob.our_pub_id(), message));
        assert!(carol.graph().contains(&invalid_accusation));

        // Verify that Carol detected malice and accused Alice of `InvalidAccusation` and Bob of
        // `Accomplice`.
        let mut our_accusations = our_votes(&carol).filter_map(|payload| match payload {
            Observation::Accusation {
                ref offender,
                malice: Malice::InvalidAccusation(hash),
            } => Some((offender, hash)),
            _ => None,
        });
        let (offender, hash) = unwrap!(our_accusations.next());

        assert_eq!(offender, alice.our_pub_id());
        assert_eq!(*hash, invalid_accusation);
        assert!(our_accusations.next().is_none());

        let b_20_hash = *unwrap!(bob.graph().get(bob.our_last_event_index())).hash();
        verify_accused_accomplice(&carol, bob.our_pub_id(), &b_20_hash, &invalid_accusation);
    }

    #[test]
    // Carol received `invalid_accusation` from Alice first, then received gossip from Bob,
    // which should have raised an accomplice accusation against Alice but didn't.
    fn accomplice_separate() {
        let (invalid_accusation, mut alice) = create_invalid_accusation();

        let mut carol = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!carol.graph().contains(&invalid_accusation));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(&PeerId::new("Carol")));
        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.graph().contains(&invalid_accusation));

        let mut bob = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.graph().contains(&invalid_accusation));

        // Send gossip from Alice to Bob
        let message = unwrap!(alice.create_gossip(&PeerId::new("Bob")));
        unwrap!(bob.handle_request(alice.our_pub_id(), message));
        assert!(bob.graph().contains(&invalid_accusation));
        // Remove the invalid accusation event (B_20), making Bob an accomplice.
        unwrap!(bob.remove_last_event());

        // Send gossip from Bob to Carol, with the accusation event missing. Carol will see that
        // the accusation event is missing, and since Bob has now created a `Requesting` event is
        // sure that Bob didn't create the accusation he should have.
        let message = unwrap!(bob.create_gossip(&PeerId::new("Carol")));
        unwrap!(carol.handle_request(bob.our_pub_id(), message));
        assert!(carol.graph().contains(&invalid_accusation));

        // Verify that Carol detected malice and accused Bob of `Accomplice`.
        let b_20_hash = *unwrap!(bob.graph().get(bob.our_last_event_index())).hash();
        verify_accused_accomplice(&carol, bob.our_pub_id(), &b_20_hash, &invalid_accusation);
    }

    #[test]
    // Carol received `invalid_accusation` from Alice first, then receive gossip from Bob, which
    // doesn't contain the malice of Alice. Carol shall not raise accusation against Bob.
    fn accomplice_negative() {
        let (invalid_accusation, mut alice) = create_invalid_accusation();

        let mut carol = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!carol.graph().contains(&invalid_accusation));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(&PeerId::new("Carol")));
        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.graph().contains(&invalid_accusation));

        let mut bob = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.graph().contains(&invalid_accusation));

        // Send gossip from Bob to Carol
        let message = unwrap!(bob.create_gossip(&PeerId::new("Carol")));
        unwrap!(carol.handle_request(bob.our_pub_id(), message));

        // Verify that Carol didn't accuse Bob of `Accomplice`.
        assert!(our_votes(&carol).all(|payload| match payload {
            Observation::Accusation {
                malice: Malice::Accomplice(_, _),
                ..
            } => false,
            _ => true,
        }));
    }

    #[test]
    fn handle_fork() {
        // Generated with RNG seed: [1573595827, 2035773878, 1331264098, 154770609].
        //
        // In this scenario, Alice creates two descendants of A_20 and sends one of them to Bob,
        // and the other one to Dave. When Bob gossips to Dave afterwards, Dave is made aware of
        // both sides of the fork and should raise an accusation.
        let mut alice0 = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        let mut bob = TestParsec::from_parsed_contents(parse_test_dot_file("bob.dot"));
        let message0 = unwrap!(alice0.create_gossip(bob.our_pub_id()));
        unwrap!(bob.handle_request(alice0.our_pub_id(), message0));

        let mut alice1 = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        let mut dave = TestParsec::from_parsed_contents(parse_test_dot_file("dave.dot"));
        let message1 = unwrap!(alice1.create_gossip(dave.our_pub_id()));
        unwrap!(dave.handle_request(alice1.our_pub_id(), message1));

        // Bob and Dave have different notions of which event is the 21st one by Alice - here
        // we save the hashes of these two events that could be considered A_21.
        let bob_a_21_hash = *unwrap!(bob.graph().find_by_short_name("A_21")).hash();
        let dave_a_21_hash = *unwrap!(dave.graph().find_by_short_name("A_21")).hash();
        assert_ne!(bob_a_21_hash, dave_a_21_hash);

        // Bob doesn't know Dave's A_21, and Dave doesn't know Bob's.
        assert!(!bob.graph().contains(&dave_a_21_hash));
        assert!(!dave.graph().contains(&bob_a_21_hash));

        // Send gossip from Bob to Dave.
        let message = unwrap!(bob.create_gossip(dave.our_pub_id()));
        unwrap!(dave.handle_request(bob.our_pub_id(), message));
        // Dave should now be aware of the other branch of the fork.
        assert!(dave.graph().contains(&bob_a_21_hash));

        // Verify that Dave detected malice and accused Alice of it.
        let (offender, hash) = unwrap!(our_votes(&dave)
            .filter_map(|payload| match payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::Fork(hash),
                } => Some((offender, hash)),
                _ => None,
            })
            .next());
        assert_eq!(offender, alice0.our_pub_id());
        assert_eq!(hash, unwrap!(bob.graph().find_by_short_name("A_20")).hash());
    }

    #[test]
    fn self_parent_by_different_creator() {
        // Generated with RNG seed: [856368386, 135728199, 764559083, 3829746197].
        let mut carol = TestParsec::from_parsed_contents(parse_test_dot_file("carol.dot"));

        // Carol creates an event with one of Bob's as the self-parent.
        let b_12_index = unwrap!(carol.graph().find_by_short_name("B_12")).event_index();
        let c_25 = unwrap!(carol.new_event_from_observation(
            b_12_index,
            Observation::OpaquePayload(Transaction::new("ABCD")),
        ));
        let c_25_hash = *c_25.hash();
        let c_25_packed = carol.pack_event(&c_25);

        let mut alice = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));

        // Try to add the event.
        assert_matches!(
            alice.unpack_and_add_event(c_25_packed.clone()),
            Err(Error::InvalidEvent)
        );

        // The invalid event should trigger an accusation vote to be raised immediately, and the
        // invalid event should not be added to the graph.
        let a_21 = unwrap!(alice.graph().find_by_short_name("A_21"));
        let expected_observation = Observation::Accusation {
            offender: carol.our_pub_id().clone(),
            malice: Malice::SelfParentByDifferentCreator(Box::new(c_25_packed)),
        };

        assert_eq!(*unwrap!(alice.event_payload(&a_21)), expected_observation);
        assert!(!alice.graph().contains(&c_25_hash));
    }

    #[test]
    fn other_parent_by_same_creator() {
        let alice_id = PeerId::new("Alice");
        let bob_id = PeerId::new("Bob");
        let genesis = btree_set![alice_id.clone(), bob_id.clone()];

        let mut alice = initialise_parsec(alice_id, &genesis, None);
        let mut bob_contents = initialise_parsed_contents(bob_id.clone(), &genesis, None);

        let (b_0_packed, b_0_index, b_0_hash) = {
            let e = unwrap!(bob_contents.graph.find_by_short_name("b_0"));
            let packed = unwrap!(e.pack(bob_contents.event_context()));
            (packed, e.event_index(), *e.hash())
        };

        let (b_1_packed, b_1_index, b_1_hash) = {
            let e = unwrap!(bob_contents.graph.find_by_short_name("b_1"));
            let packed = unwrap!(e.pack(bob_contents.event_context()));
            (packed, e.event_index(), *e.hash())
        };

        let b_2 = unwrap!(Event::new_from_request(
            b_1_index,
            b_0_index,
            bob_contents.event_context()
        ));
        let b_2_hash = *b_2.hash();
        let b_2_packed = unwrap!(b_2.pack(bob_contents.event_context()));

        let b_1 = unwrap!(bob_contents.remove_last_event());
        assert_eq!(*b_1.hash(), b_1_hash);

        let b_0 = unwrap!(bob_contents.remove_last_event());
        assert_eq!(*b_0.hash(), b_0_hash);

        unwrap!(alice.unpack_and_add_event(b_0_packed));
        unwrap!(alice.unpack_and_add_event(b_1_packed));

        // This should fail, as B_2 has other-parent by the same creator.
        assert_matches!(
            alice.unpack_and_add_event(b_2_packed),
            Err(Error::InvalidEvent)
        );

        // Alice should raise accusation against Bob
        let (offender, event) = unwrap!(our_votes(&alice)
            .filter_map(|payload| match payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::OtherParentBySameCreator(event),
                } => Some((offender, event)),
                _ => None,
            })
            .next());

        assert_eq!(*offender, bob_id);
        assert_eq!(event.compute_hash(), b_2_hash);

        // B_2 should not have been inserted into Alice's graph
        assert!(!alice.graph().contains(&b_2_hash));
    }

    #[test]
    fn premature_gossip() {
        // Generated with RNG seed: [411278735, 3293288956, 208850454, 2872654992].
        // Copied from add_peer
        let mut parsed_contents = parse_test_dot_file("alice.dot");

        // The final decision to add Frank is reached in E_25, so we remove this event.
        let _e_25 = unwrap!(parsed_contents.remove_last_event());

        let mut alice = TestParsec::from_parsed_contents(parsed_contents);
        let genesis_group: BTreeSet<_> = alice
            .peer_list()
            .all_ids()
            .map(|(_, id)| id.clone())
            .collect();

        let alice_id = PeerId::new("Alice");
        let fred_id = PeerId::new("Fred");
        assert!(!alice
            .peer_list()
            .all_ids()
            .any(|(_, peer_id)| *peer_id == fred_id));

        let alice_snapshot = Snapshot::new(&alice);

        // Try calling `create_gossip()` for a peer which doesn't exist yet.
        assert_matches!(alice.create_gossip(&fred_id), Err(Error::UnknownPeer));
        assert_eq!(alice_snapshot, Snapshot::new(&alice));

        // We'll modify Alice's peer list to allow her to create gossip for Fred
        alice.add_peer(fred_id.clone(), PeerState::RECV | PeerState::VOTE);

        // Construct Fred's Parsec instance.
        let mut fred = TestParsec::from_existing(
            fred_id.clone(),
            &genesis_group,
            &genesis_group,
            ConsensusMode::Supermajority,
        );

        // Check that Fred has no events that Alice has
        assert!(alice
            .graph()
            .iter()
            .all(|ev| !fred.graph().contains(ev.inner().hash())));

        // Now Alice will prematurely gossip to Fred
        let request = unwrap!(alice.create_gossip(&fred_id));
        let result = fred.handle_request(&alice_id, request);

        // check that Fred detected premature gossip
        assert_matches!(result, Err(Error::PrematureGossip));

        // Check that Fred has all the events that Alice has
        assert!(alice
            .graph()
            .iter()
            .all(|ev| fred.graph().contains(ev.inner().hash())));
    }

    #[test]
    fn invalid_self_parent() {
        let alice_id = PeerId::new("Alice");
        let bob_id = PeerId::new("Bob");
        let genesis = btree_set![alice_id.clone(), bob_id.clone()];

        let mut alice = EventContext::new(alice_id.clone());
        let _ = alice
            .peer_list
            .add_peer(bob_id.clone(), PeerState::active());

        let a_0 = Event::new_initial(alice.as_ref());
        let a_0_index = alice.graph.insert(a_0).event_index();

        let a_1 = unwrap!(Event::new_from_requesting(
            a_0_index,
            &bob_id,
            alice.as_ref(),
        ));
        let a_1_hash = *a_1.hash();
        let a_1_packed = unwrap!(a_1.pack(alice.as_ref()));

        // Construct a request which contains an event but not its self-parent.
        let request = Request {
            packed_events: vec![a_1_packed],
        };

        // Create another Parsec and handle the above request. It should return error.
        let mut bob = TestParsec::from_genesis(bob_id, &genesis, ConsensusMode::Supermajority);
        let result = bob.handle_request(&alice_id, request);
        assert_matches!(result, Err(Error::UnknownSelfParent));

        // Verify that the invalid event has not been added to Bob:
        assert!(bob.graph().get_index(&a_1_hash).is_none());
    }

    #[test]
    fn invalid_other_parent() {
        let alice_id = PeerId::new("Alice");
        let bob_id = PeerId::new("Bob");
        let carol_id = PeerId::new("Carol");
        let genesis = btree_set![alice_id.clone(), bob_id.clone(), carol_id.clone()];

        let mut alice = EventContext::new(alice_id.clone());
        let _ = alice
            .peer_list
            .add_peer(bob_id.clone(), PeerState::active());

        let bob = EventContext::new(bob_id.clone());

        let a_0 = Event::new_initial(alice.as_ref());
        let a_0_index = alice.graph.insert(a_0).event_index();
        let a_0 = unwrap!(alice.graph.get(a_0_index));
        let a_0_packed = unwrap!(a_0.pack(alice.as_ref()));

        let b_0 = Event::new_initial(bob.as_ref());
        let b_0 = unwrap!(b_0.pack(bob.as_ref()));
        let b_0 = unwrap!(unwrap!(Event::unpack(b_0, alice.as_ref()))).event;
        let b_0_index = alice.graph.insert(b_0).event_index();

        let a_1 = unwrap!(Event::new_from_request(
            a_0_index,
            b_0_index,
            alice.as_ref()
        ));
        let a_1_hash = *a_1.hash();
        let a_1_packed = unwrap!(a_1.pack(alice.as_ref()));

        // Construct a request which contains an event but not its other-parent.
        let request = Request {
            packed_events: vec![a_0_packed, a_1_packed],
        };

        // Create another Parsec and handle the above request. It should return error.
        let mut carol = TestParsec::from_genesis(carol_id, &genesis, ConsensusMode::Supermajority);
        let result = carol.handle_request(&alice_id, request);
        assert_matches!(result, Err(Error::UnknownOtherParent));

        // Verify that the invalid event has not been added to Carol:
        assert!(carol.graph().get_index(&a_1_hash).is_none());
    }
}
