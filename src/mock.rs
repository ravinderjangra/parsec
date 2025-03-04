// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    id::{PublicId, SecretId},
    network_event::NetworkEvent,
};
use rand::{
    distributions::{Alphanumeric, Distribution, Standard},
    Rng,
};
use std::{
    cmp::Ordering,
    collections::hash_map::DefaultHasher,
    fmt::{self, Debug, Display, Formatter},
    hash::{Hash, Hasher},
};

pub const NAMES: &[&str] = &[
    "Alice", "Bob", "Carol", "Dave", "Eric", "Fred", "Gina", "Hank", "Iris", "Judy", "Kent",
    "Lucy", "Mike", "Nina", "Oran", "Paul", "Quin", "Rose", "Stan", "Tina", "Ulf", "Vera", "Will",
    "Xaviera", "Yakov", "Zaida", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
];

lazy_static! {
    static ref PEERS: Vec<PeerId> = NAMES
        .iter()
        .map(|name| PeerId::new_with_keypair(name))
        .collect();
}

/// **NOT FOR PRODUCTION USE**: Mock type implementing `PublicId` and `SecretId` traits.  For
/// non-mocks, these two traits must be implemented by two separate types; a public key and secret
/// key respectively.
#[derive(Clone, Serialize, Deserialize)]
pub struct PeerId {
    id: String,
    public_key: PublicKey,
    secret_key: SecretKey,
}

impl PeerId {
    pub fn new(id: &str) -> Self {
        PEERS
            .iter()
            .find(|peer| peer.id == id)
            .cloned()
            .unwrap_or_else(|| PeerId::new_with_keypair(id))
    }

    pub fn named_peer_ids() -> &'static [PeerId] {
        &PEERS
    }

    #[cfg(not(feature = "mock"))]
    fn new_with_keypair(id: &str) -> Self {
        let (public_key, secret_key) = gen_keypair();
        Self {
            id: id.to_owned(),
            public_key,
            secret_key,
        }
    }

    #[cfg(feature = "mock")]
    fn new_with_keypair(id: &str) -> Self {
        let (public_key, secret_key) = derive_keypair(id.as_bytes());
        Self {
            id: id.to_string(),
            public_key,
            secret_key,
        }
    }

    // Only being used by the dot_parser.
    #[cfg(any(test, feature = "testing"))]
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn from_index(peer_index: usize) -> Option<Self> {
        NAMES.get(peer_index).map(|name| PeerId::new(name))
    }
}

impl Debug for PeerId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id)
    }
}

impl Hash for PeerId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.public_key.hash(state);
    }
}

impl PartialEq for PeerId {
    fn eq(&self, other: &PeerId) -> bool {
        self.id == other.id && self.public_key == other.public_key
    }
}

impl Eq for PeerId {}

impl PartialOrd for PeerId {
    fn partial_cmp(&self, other: &PeerId) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PeerId {
    fn cmp(&self, other: &PeerId) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl PublicId for PeerId {
    type Signature = Signature;

    fn verify_signature(&self, signature: &Self::Signature, data: &[u8]) -> bool {
        let mut hasher = DefaultHasher::new();
        hasher.write(data);
        hasher.write(&self.public_key.0);
        let hash = hasher.finish().to_le_bytes();

        signature.0[..hash.len()] == hash
    }
}

impl SecretId for PeerId {
    type PublicId = PeerId;

    fn public_id(&self) -> &Self::PublicId {
        &self
    }

    fn sign_detached(&self, data: &[u8]) -> Signature {
        let mut hasher = DefaultHasher::new();
        hasher.write(data);
        hasher.write(&self.secret_key.0);
        let hash = hasher.finish().to_le_bytes();

        let mut signature = Signature([0; SIGNATURE_LENGTH]);
        signature.0[..hash.len()].copy_from_slice(&hash[..]);
        signature
    }

    #[cfg(not(feature = "mock"))]
    fn encrypt<M: AsRef<[u8]>>(&self, _to: &Self::PublicId, msg: M) -> Option<Vec<u8>> {
        // Pass through: We cannot store encryption keys as they are not reproductible.
        // This code is only used for test.
        Some(msg.as_ref().to_vec())
    }

    #[cfg(not(feature = "mock"))]
    fn decrypt(&self, _from: &Self::PublicId, ct: &[u8]) -> Option<Vec<u8>> {
        // Pass through: We cannot store encryption keys as they are not reproductible.
        // This code is only used for test.
        Some(ct.to_vec())
    }

    #[cfg(feature = "mock")]
    fn encrypt<M: AsRef<[u8]>>(&self, to: &Self::PublicId, msg: M) -> Option<Vec<u8>> {
        let shared_secret = SharedSecret::new(&to.public_key, &self.secret_key);
        Some(
            msg.as_ref()
                .iter()
                .chain(shared_secret.0.iter())
                .copied()
                .collect(),
        )
    }

    #[cfg(feature = "mock")]
    fn decrypt(&self, from: &Self::PublicId, ct: &[u8]) -> Option<Vec<u8>> {
        let shared_secret = SharedSecret::new(&from.public_key, &self.secret_key);

        if ct.ends_with(&shared_secret.0) {
            Some(ct[..(ct.len() - shared_secret.0.len())].to_vec())
        } else {
            None
        }
    }
}

/// **NOT FOR PRODUCTION USE**: Mock type implementing `NetworkEvent` trait.
#[derive(Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Transaction(String);

impl Transaction {
    pub fn new<T: Into<String>>(id: T) -> Self {
        Transaction(id.into())
    }
}

impl NetworkEvent for Transaction {}

impl Display for Transaction {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Transaction({})", self.0)
    }
}

impl Debug for Transaction {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl Distribution<Transaction> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Transaction {
        Transaction(rng.sample_iter(Alphanumeric).take(5).collect())
    }
}

/// **NOT FOR PRODUCTION USE**: Returns a collection of mock node IDs with human-readable names.
pub fn create_ids(count: usize) -> Vec<PeerId> {
    assert!(count <= NAMES.len());
    NAMES.iter().take(count).cloned().map(PeerId::new).collect()
}

const SIGNATURE_LENGTH: usize = 32;
const KEY_LENGTH: usize = 32;

// **NOT FOR PRODUCTION USE**: Mock public key.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct PublicKey([u8; KEY_LENGTH]);

// **NOT FOR PRODUCTION USE**: Mock secret key.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretKey([u8; KEY_LENGTH]);

// **NOT FOR PRODUCTION USE**: Mock signature.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Signature([u8; SIGNATURE_LENGTH]);

impl Debug for Signature {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Signature(..)")
    }
}

#[cfg(feature = "mock")]
struct SharedSecret([u8; KEY_LENGTH]);

#[cfg(feature = "mock")]
impl SharedSecret {
    fn new(pk: &PublicKey, sk: &SecretKey) -> Self {
        let mut result = Self([0; KEY_LENGTH]);
        for i in 0..KEY_LENGTH {
            result.0[i] = pk.0[i] ^ sk.0[i];
        }

        result
    }
}

#[cfg(not(feature = "mock"))]
fn gen_keypair() -> (PublicKey, SecretKey) {
    let mut rng = crate::dev_utils::thread_rng();
    let bytes: [u8; KEY_LENGTH] = rng.gen();
    (PublicKey(bytes), SecretKey(bytes))
}

#[cfg(feature = "mock")]
fn derive_keypair(seed: &[u8]) -> (PublicKey, SecretKey) {
    use crate::hash::Hash;
    let hash = Hash::from(seed);
    (PublicKey(*hash.as_bytes()), SecretKey(*hash.as_bytes()))
}
