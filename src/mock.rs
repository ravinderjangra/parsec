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
use rand::{Rand, Rng};
use safe_crypto::{gen_sign_keypair, PublicSignKey, SecretSignKey, Signature as SafeSignature};
use std::{
    cmp::Ordering,
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
        .map(|name| PeerId::new_with_random_keypair(name))
        .collect();
}

/// **NOT FOR PRODUCTION USE**: Mock signature type.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Signature(SafeSignature);

impl Debug for Signature {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "..")
    }
}

/// **NOT FOR PRODUCTION USE**: Mock type implementing `PublicId` and `SecretId` traits.  For
/// non-mocks, these two traits must be implemented by two separate types; a public key and secret
/// key respectively.
#[derive(Clone, Serialize, Deserialize)]
pub struct PeerId {
    id: String,
    pub_sign: PublicSignKey,
    sec_sign: SecretSignKey,
}

impl PeerId {
    pub fn new(id: &str) -> Self {
        PEERS
            .iter()
            .find(|peer| peer.id == id)
            .cloned()
            .unwrap_or_else(|| PeerId::new_with_keypair(id))
    }

    pub fn new_with_random_keypair(id: &str) -> Self {
        let (pub_sign, sec_sign) = gen_sign_keypair();
        Self {
            id: id.to_string(),
            pub_sign,
            sec_sign,
        }
    }

    #[cfg(not(feature = "mock"))]
    fn new_with_keypair(id: &str) -> Self {
        Self::new_with_random_keypair(id)
    }

    #[cfg(feature = "mock")]
    fn new_with_keypair(id: &str) -> Self {
        use crate::hash::Hash;
        use safe_crypto::{gen_sign_keypair_from_seed, Seed};

        let name_hash = Hash::from(id.as_bytes());
        let (pub_sign, sec_sign) =
            gen_sign_keypair_from_seed(&Seed::from_bytes(*name_hash.as_bytes()));
        Self {
            id: id.to_string(),
            pub_sign,
            sec_sign,
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
        self.pub_sign.hash(state);
    }
}

impl PartialEq for PeerId {
    fn eq(&self, other: &PeerId) -> bool {
        self.id == other.id && self.pub_sign == other.pub_sign
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
        self.pub_sign.verify_detached(&signature.0, data)
    }
}

impl SecretId for PeerId {
    type PublicId = PeerId;
    fn public_id(&self) -> &Self::PublicId {
        &self
    }
    fn sign_detached(&self, data: &[u8]) -> Signature {
        Signature(self.sec_sign.sign_detached(data))
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
        use safe_crypto::{PublicEncryptKey, SecretEncryptKey};
        // Create a deterministic key based on safe_crypto mock implementation.
        let to_pub_encrypt = PublicEncryptKey::from_bytes(to.pub_sign.into_bytes());
        let self_sec_encrypt = SecretEncryptKey::from_bytes(self.pub_sign.into_bytes());

        let shared_secret = self_sec_encrypt.shared_secret(&to_pub_encrypt);

        // Cannot use encrypt_bytes/decrypt_bytes because encrypt add a radom nonce
        // that cannot be replayed.
        // Otherwise we would use `shared_secret.encrypt_bytes(msg.as_ref()).ok()`
        let fake_encrypt = || {
            let mut msg = msg.as_ref().to_vec();
            msg.extend(shared_secret.into_bytes().iter());
            Some(msg)
        };

        fake_encrypt()
    }

    #[cfg(feature = "mock")]
    fn decrypt(&self, from: &Self::PublicId, ct: &[u8]) -> Option<Vec<u8>> {
        use safe_crypto::{PublicEncryptKey, SecretEncryptKey};
        // Create a deterministic key based on safe_crypto mock implementation.
        let from_pub_encrypt = PublicEncryptKey::from_bytes(from.pub_sign.into_bytes());
        let self_sec_encrypt = SecretEncryptKey::from_bytes(self.pub_sign.into_bytes());

        let shared_secret = self_sec_encrypt.shared_secret(&from_pub_encrypt);

        // Cannot use encrypt_bytes/decrypt_bytes because encrypt add a radom nonce
        // that cannot be replayed.
        // Otherwise we would use `shared_secret.decrypt_bytes(ct).ok()`
        let fake_decrypt = || {
            let shared_secret_bytes = shared_secret.into_bytes();
            if ct.ends_with(&shared_secret_bytes) {
                Some(ct[0..(ct.len() - shared_secret_bytes.len())].to_vec())
            } else {
                None
            }
        };

        fake_decrypt()
    }
}

/// **NOT FOR PRODUCTION USE**: Mock type implementing `NetworkEvent` trait.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
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

impl Rand for Transaction {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        Transaction(rng.gen_ascii_chars().take(5).collect())
    }
}

/// **NOT FOR PRODUCTION USE**: Returns a collection of mock node IDs with human-readable names.
pub fn create_ids(count: usize) -> Vec<PeerId> {
    assert!(count <= NAMES.len());
    NAMES.iter().take(count).cloned().map(PeerId::new).collect()
}
