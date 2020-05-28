// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use rand::{Error, Rng, RngCore, SeedableRng};
use rand_core::impls;
use rand_xorshift::XorShiftRng;
use std::{cell::RefCell, fmt};

pub trait RngDebug: RngCore + fmt::Debug {}

impl RngDebug for XorShiftRng {}

#[derive(Clone, Copy, Debug)]
pub enum RngChoice {
    Random,
    Seeded([u32; 4]),
}

/// Create a new Rng: Use once per test.
pub fn new_common_rng(seed: RngChoice) -> XorShiftRng {
    let seed = match seed {
        RngChoice::Random => rand::thread_rng().gen(),
        RngChoice::Seeded(seed) => seed,
    };

    println!("Seed: {:?}", seed);

    let mut rng = XorShiftRng::from_seed(convert_seed(seed));
    RNG.with(|thread_rng| *thread_rng.borrow_mut() = new_rng(&mut rng));
    rng
}

/// Create a new RNG using a seed generated from random data provided by `rng`.
pub fn new_rng<R: RngCore>(rng: &mut R) -> XorShiftRng {
    let new_seed = [
        rng.next_u32().wrapping_add(rng.next_u32()),
        rng.next_u32().wrapping_add(rng.next_u32()),
        rng.next_u32().wrapping_add(rng.next_u32()),
        rng.next_u32().wrapping_add(rng.next_u32()),
    ];
    XorShiftRng::from_seed(convert_seed(new_seed))
}

pub fn thread_rng() -> XorShiftRng {
    RNG.with(|rng| new_rng(&mut *rng.borrow_mut()))
}

thread_local! {
    static RNG: RefCell<XorShiftRng> = RefCell::new(XorShiftRng::from_seed(rand::thread_rng().gen()));
}

/// Create a RNG that will replay the given value and when complete will panic if more value needed.
pub struct ReplayRng {
    values: Vec<u32>,
    index: usize,
}

impl ReplayRng {
    /// Create ReplayRng that will replay the given `values`.
    pub fn new(values: Vec<u32>) -> Self {
        Self { values, index: 0 }
    }
}

impl RngCore for ReplayRng {
    fn next_u32(&mut self) -> u32 {
        let value = unwrap!(self.values.get(self.index));
        self.index += 1;
        *value
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

// Convert the XorShiftRng seed from the old to the new format.
fn convert_seed(src: [u32; 4]) -> [u8; 16] {
    let mut bytes = [0; 16];
    let mut index = 0;
    for num in src.iter() {
        for num_byte in &num.to_le_bytes() {
            bytes[index] = *num_byte;
            index += 1;
        }
    }
    bytes
}
