// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    dev_utils::{
        network::{ConsensusError, Network},
        new_common_rng, RngChoice, RngDebug, Schedule,
    },
    observation::ConsensusMode,
};
use std::fmt;

pub struct Environment {
    /// The network for test
    pub network: Network,
    /// Rng for random execution
    pub rng: Box<RngDebug>,
    /// Additional Rng used for additional randomness without breaking seed from `rng`.
    /// It can be used to create Parsec instances new `Rng`.
    pub rng2: Box<RngDebug>,
}

impl Environment {
    /// Initialise the test environment. The random number generator will be seeded with `seed`
    /// or randomly if this is `SeededRandom`.
    pub fn with_consensus_mode(seed: RngChoice, consensus_mode: ConsensusMode) -> Self {
        let rng = new_common_rng(seed);
        let rng2 = new_common_rng(seed);
        let network = Network::new(consensus_mode);

        Self { network, rng, rng2 }
    }

    pub fn new(seed: RngChoice) -> Self {
        Self::with_consensus_mode(seed, ConsensusMode::Supermajority)
    }

    pub fn execute_schedule(&mut self, schedule: Schedule) -> Result<(), ConsensusError> {
        self.network
            .execute_schedule(&mut self.rng, &mut self.rng2, schedule)
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
