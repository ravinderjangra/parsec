// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod abstract_event;
mod cause;
mod content;
mod event;
mod event_context;
mod event_hash;
mod event_utils;
mod graph;
mod messages;
mod packed_event;

#[cfg(any(test, feature = "testing", feature = "dump-graphs"))]
pub(super) use self::cause::Cause;
#[cfg(any(test, feature = "testing"))]
pub(super) use self::event::CauseInput;
#[cfg(any(all(test, feature = "mock"), feature = "dump-graphs"))]
pub(super) use self::graph::snapshot::GraphSnapshot;
pub(super) use self::{
    abstract_event::AbstractEventRef,
    event::Event,
    event_context::EventContextRef,
    graph::{EventIndex, Graph, IndexedEventRef},
};
pub use self::{
    event_hash::EventHash,
    messages::{Request, Response},
    packed_event::PackedEvent,
};
