// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    cmp::Ordering,
    fmt::{self, Debug, Formatter},
};
use threshold_crypto::{PublicKeySet, SecretKeyShare};

#[derive(Clone)]
/// DKG result
pub struct DkgResult {
    /// Public key set to verify threshold signatures
    pub public_key_set: PublicKeySet,
    /// Secret Key share: None if the node was not participating in the DKG and did not receive
    /// encrypted shares.
    pub secret_key_share: Option<SecretKeyShare>,
}

impl DkgResult {
    /// Create DkgResult from components
    pub fn new(public_key_set: PublicKeySet, secret_key_share: Option<SecretKeyShare>) -> Self {
        Self {
            public_key_set,
            secret_key_share,
        }
    }
}

impl Debug for DkgResult {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "DkgResult({:?}, {})",
            self.public_key_set,
            self.secret_key_share.is_some()
        )
    }
}

#[derive(Clone)]
/// Wrapper providing necessary functionality to be stored in an Observation.
/// Do not add these directly to DkgResult as they are not semantically correct for it.
/// Ignore secret key for all of these: blocks are expected to be the same between peers.
pub struct DkgResultWrapper(pub DkgResult);

impl Debug for DkgResultWrapper {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl DkgResultWrapper {
    fn comparison_value(&self) -> &PublicKeySet {
        // Ignore the secret_key_share as they will be different for each participants,
        // non participants will have None.
        &self.0.public_key_set
    }
}

impl PartialEq for DkgResultWrapper {
    fn eq(&self, rhs: &Self) -> bool {
        self.comparison_value().eq(&rhs.comparison_value())
    }
}

impl Eq for DkgResultWrapper {}

impl PartialOrd for DkgResultWrapper {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        self.comparison_value().partial_cmp(&rhs.comparison_value())
    }
}

impl Ord for DkgResultWrapper {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.comparison_value().cmp(&rhs.comparison_value())
    }
}

impl Serialize for DkgResultWrapper {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.public_key_set.serialize(s)
    }
}

impl<'a> Deserialize<'a> for DkgResultWrapper {
    fn deserialize<D: Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        PublicKeySet::deserialize(deserializer).map(|public_key_set| {
            DkgResultWrapper(DkgResult {
                public_key_set,
                secret_key_share: None,
            })
        })
    }
}
