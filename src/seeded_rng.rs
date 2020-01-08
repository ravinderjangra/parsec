// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use maidsafe_utilities::SeededRng as InnerRng;
use rand::{Error, RngCore};
use rand_maidsafe_utilities::Rng;
use std::fmt::{self, Debug, Formatter};

// Wrapper for maidsafe_utilities::SeededRng that is compatible with the latest rand crate.
pub struct SeededRng(InnerRng);

#[cfg(any(test, feature = "testing"))]
impl SeededRng {
    pub fn new() -> Self {
        Self(InnerRng::new())
    }

    pub fn from_seed(seed: [u32; 4]) -> Self {
        Self(InnerRng::from_seed(seed))
    }
}

#[cfg(all(test, not(feature = "mock")))]
impl SeededRng {
    pub fn thread_rng() -> Self {
        Self(InnerRng::thread_rng())
    }
}

impl Debug for SeededRng {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
