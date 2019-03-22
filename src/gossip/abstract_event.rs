// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{observation::ObservationKey, peer_list::PeerIndex};

/// Provide a small interface to Event not dependent on PublicId. Serves as a test seam.
pub(crate) trait AbstractEventRef<'a>: Copy {
    /// The vote payload_key for an Observation event
    fn payload_key(self) -> Option<&'a ObservationKey>
    where
        Self: Sized;

    /// The PeerIndex for this event creator
    fn creator(self) -> PeerIndex
    where
        Self: Sized;

    // Index of this event relative to other events by the same creator.
    fn index_by_creator(self) -> usize
    where
        Self: Sized;
}
