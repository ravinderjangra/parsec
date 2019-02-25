// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(feature = "malice-detection")]
use crate::error::{Error, Result};
#[cfg(feature = "malice-detection")]
use crate::gossip::cause::Cause;
use crate::gossip::packed_event::PackedEvent;
#[cfg(feature = "malice-detection")]
use crate::gossip::{EventContextRef, IndexedEventRef};
use crate::id::PublicId;
#[cfg(feature = "malice-detection")]
use crate::id::SecretId;
use crate::network_event::NetworkEvent;
#[cfg(feature = "malice-detection")]
use crate::observation::Observation;
#[cfg(feature = "malice-detection")]
use crate::peer_list::PeerIndex;

/// A gossip request message.
#[serde(bound = "")]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Request<T: NetworkEvent, P: PublicId> {
    pub(crate) packed_events: Vec<PackedEvent<T, P>>,
}

impl<T: NetworkEvent, P: PublicId> Request<T, P> {
    pub(crate) fn new(packed_events: Vec<PackedEvent<T, P>>) -> Self {
        Self { packed_events }
    }

    /// Returns `Ok` if the final event is a `Requesting` by `sender` targeting us, and for which we
    /// have not yet recorded an associated `Request` event.  Otherwise returns `Err`.
    #[cfg(feature = "malice-detection")]
    pub(crate) fn validate<S: SecretId<PublicId = P>>(
        &self,
        sender: &P,
        ctx: EventContextRef<T, S>,
    ) -> Result<()> {
        let packed_event = self.packed_events.last().ok_or(Error::InvalidMessage)?;

        if packed_event.content.creator != *sender {
            return Err(Error::InvalidMessage);
        }

        if let Cause::Requesting { ref recipient, .. } = packed_event.content.cause {
            if recipient != ctx.peer_list.our_pub_id() {
                return Err(Error::InvalidMessage);
            }
        } else {
            return Err(Error::InvalidMessage);
        }

        // We may validly have received this request after already finding out about all the
        // events in it.  In this case, check that the sender's `Requesting` event is currently
        // missing its associated `Request` created by us in the graph.  Otherwise, this message has
        // already been handled by us.
        let sender_requesting_hash = packed_event.compute_hash();
        if ctx
            .graph
            .get_index(&sender_requesting_hash)
            .and_then(|index| ctx.graph.get(index))
            .map(|event| ctx.graph.is_awaiting_associated_event(event))
            .unwrap_or(true)
        {
            return Ok(());
        }
        Err(Error::DuplicateMessage)
    }
}

/// A gossip response message.
#[serde(bound = "")]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Response<T: NetworkEvent, P: PublicId> {
    pub(crate) packed_events: Vec<PackedEvent<T, P>>,
}

impl<T: NetworkEvent, P: PublicId> Response<T, P> {
    pub(crate) fn new(packed_events: Vec<PackedEvent<T, P>>) -> Self {
        Self { packed_events }
    }

    /// Returns `Ok` if:
    ///   * the final event is a `Request` by `sender`
    ///   * with its other_parent as a `Requesting` event created by us, targeting `sender` and
    ///   * for which we have not yet recorded an associated `Response` event
    ///   * or if such an event immediately precedes a series of accusations by `sender`.
    /// Otherwise returns `Err`.
    #[cfg(feature = "malice-detection")]
    pub(crate) fn validate<S: SecretId<PublicId = P>>(
        &self,
        sender: &P,
        ctx: EventContextRef<T, S>,
    ) -> Result<()> {
        for packed_event in self.packed_events.iter().rev() {
            if packed_event.content.creator != *sender {
                break;
            }

            match packed_event.content.cause {
                Cause::Request {
                    ref other_parent, ..
                } => {
                    let is_valid = |event: IndexedEventRef<P>| {
                        event.creator() == PeerIndex::OUR
                            && event.requesting_recipient() == ctx.peer_list.get_index(sender)
                            && ctx.graph.is_awaiting_associated_event(event)
                    };
                    if ctx
                        .graph
                        .get_index(other_parent)
                        .and_then(|index| ctx.graph.get(index))
                        .map(is_valid)
                        .unwrap_or(false)
                    {
                        return Ok(());
                    }

                    // We may validly have received this response after already finding out about
                    // all the events in it.  In this case, check that the sender's `Request` event
                    // is currently missing its associated `Response` created by us in the graph.
                    // Otherwise, this message has already been handled by us.
                    let sender_request_hash = packed_event.compute_hash();
                    if ctx
                        .graph
                        .get_index(&sender_request_hash)
                        .and_then(|index| ctx.graph.get(index))
                        .map(|event| ctx.graph.is_awaiting_associated_event(event))
                        .unwrap_or(false)
                    {
                        return Ok(());
                    } else {
                        return Err(Error::DuplicateMessage);
                    }
                }
                Cause::Observation { ref vote, .. } => match vote.payload() {
                    Observation::Accusation { .. } => continue,
                    _ => break,
                },
                _ => break,
            }
        }
        Err(Error::InvalidMessage)
    }
}
