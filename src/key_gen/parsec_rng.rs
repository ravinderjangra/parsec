// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use rand::{Error, RngCore};
#[cfg(feature = "dump-graphs")]
use rand_core::impls;

/// Secure RNG used by Parsec for DKG:
/// If feature = "dump-graphs" is enabled, allow dumping the produced value to allow replay.
pub struct ParsecRng {
    secure_rng: Box<dyn RngCore>,
    #[cfg(feature = "dump-graphs")]
    generated_values: Vec<u32>,
}

impl ParsecRng {
    /// Create ParsecRng that will output value from the secure_rng.
    /// `secure_rng`: a cryptographically secure RNG.
    pub fn new(secure_rng: Box<dyn RngCore>) -> Self {
        Self {
            secure_rng,
            #[cfg(feature = "dump-graphs")]
            generated_values: Vec::new(),
        }
    }

    /// All the value generated so far.
    #[cfg(feature = "dump-graphs")]
    pub fn generated_values(&self) -> &Vec<u32> {
        &self.generated_values
    }
}

#[cfg(not(feature = "dump-graphs"))]
impl RngCore for ParsecRng {
    fn next_u32(&mut self) -> u32 {
        self.secure_rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.secure_rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.secure_rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.secure_rng.try_fill_bytes(dest)
    }
}

#[cfg(feature = "dump-graphs")]
impl RngCore for ParsecRng {
    fn next_u32(&mut self) -> u32 {
        let next = self.secure_rng.next_u32();
        self.generated_values.push(next);
        next
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
