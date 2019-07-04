// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    dev_utils::network::Network, dev_utils::new_common_rng, dev_utils::RngChoice,
    dev_utils::RngDebug, observation::ConsensusMode,
};
use std::fmt;

pub struct Environment {
    pub network: Network,
    pub rng: Box<RngDebug>,
}

impl Environment {
    /// Initialise the test environment. The random number generator will be seeded with `seed`
    /// or randomly if this is `SeededRandom`.
    pub fn with_consensus_mode(seed: RngChoice, consensus_mode: ConsensusMode) -> Self {
        let rng = new_common_rng(seed);
        let network = Network::new(consensus_mode);

        Self { network, rng }
    }

    pub fn new(seed: RngChoice) -> Self {
        Self::with_consensus_mode(seed, ConsensusMode::Supermajority)
    }
}

impl fmt::Debug for Environment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Environment({} peers, {:?})",
            self.network.peers.len(),
            self.rng
        )
    }
}
