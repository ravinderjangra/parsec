// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod ancestors;
mod event_index;
mod event_ref;

pub(crate) use self::ancestors::Ancestors;
pub(crate) use self::event_index::EventIndex;
pub(crate) use self::event_ref::IndexedEventRef;

use super::{event::Event, event_hash::EventHash};
use crate::id::PublicId;
use std::collections::btree_map::{BTreeMap, Entry};
use std::collections::BTreeSet;

/// The gossip graph.
#[derive(Eq, PartialEq, Debug)]
pub(crate) struct Graph<P: PublicId> {
    events: Vec<Event<P>>,
    indices: BTreeMap<EventHash, EventIndex>,
}

impl<P: PublicId> Default for Graph<P> {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            indices: BTreeMap::new(),
        }
    }
}

impl<P: PublicId> Graph<P> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get index of an event with the given hash.
    pub fn get_index(&self, hash: &EventHash) -> Option<EventIndex> {
        self.indices.get(hash).cloned()
    }

    /// Checks whether this graph contains an event with the given hash.
    pub fn contains(&self, hash: &EventHash) -> bool {
        self.indices.contains_key(hash)
    }

    /// Insert new event into the graph.
    /// Returns `IndexedEventRef` to the newly inserted event.
    /// If the event was already present in the graph, does not overwrite it, just returns an
    /// `IndexedEventRef` to it.
    pub fn insert(&mut self, event: Event<P>) -> IndexedEventRef<P> {
        let index = match self.indices.entry(*event.hash()) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let index = EventIndex(self.events.len());

                #[cfg(any(test, feature = "testing"))]
                assert_ne!(index, EventIndex::PHONY);

                self.events.push(event);
                *entry.insert(index)
            }
        };

        IndexedEventRef {
            index,
            event: &self.events[index.0],
        }
    }

    /// Gets `Event` with the given `index`, if it exists.
    pub fn get(&self, index: EventIndex) -> Option<IndexedEventRef<P>> {
        self.events
            .get(index.0)
            .map(|event| IndexedEventRef { index, event })
    }

    /// Number of events in this graph.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Iterator over all events in this graph. Yields `IndexedEventRef`s.
    pub fn iter(&self) -> Iter<P> {
        self.iter_from(0)
    }

    /// Iterator over events in this graph starting at the given topological index.
    pub fn iter_from(&self, start_index: usize) -> Iter<P> {
        Iter {
            events: &self.events,
            index: start_index,
        }
    }

    /// Iterator over event indices starting at the given topological index.
    pub fn indices_from(&self, start_index: usize) -> impl Iterator<Item = EventIndex> {
        (start_index..self.events.len()).map(EventIndex)
    }

    /// Returns self-parent of the given event, if any.
    pub fn self_parent<E: AsRef<Event<P>>>(&self, event: E) -> Option<IndexedEventRef<P>> {
        event
            .as_ref()
            .self_parent()
            .and_then(|index| self.get(index))
    }

    /// Returns other-parent of the given event, if any.
    pub fn other_parent<E: AsRef<Event<P>>>(&self, event: E) -> Option<IndexedEventRef<P>> {
        event
            .as_ref()
            .other_parent()
            .and_then(|index| self.get(index))
    }

    /// Iterator over all ancestors of the given event (including itself) in reverse topological
    /// order.
    pub fn ancestors<'a>(&'a self, event: IndexedEventRef<'a, P>) -> Ancestors<'a, P> {
        let mut queue = BTreeSet::new();
        let _ = queue.insert(event);

        Ancestors {
            graph: self,
            queue,
            visited: vec![false; event.topological_index() + 1],
        }
    }

    /// Returns whether `x` is descendant of `y`.
    pub fn is_descendant(&self, x: IndexedEventRef<P>, y: IndexedEventRef<P>) -> bool {
        x.is_descendant_of(y).unwrap_or_else(|| {
            self.ancestors(x)
                .take_while(|e| e.topological_index() >= y.topological_index())
                .any(|e| e.topological_index() == y.topological_index())
        })
    }
}

#[cfg(test)]
impl<P: PublicId> Graph<P> {
    /// Remove the topologically last event.
    pub fn remove_last(&mut self) -> Option<(EventIndex, Event<P>)> {
        let event = self.events.pop()?;
        let _ = self.indices.remove(event.hash());
        Some((EventIndex(self.events.len()), event))
    }
}

impl<P: PublicId> IntoIterator for Graph<P> {
    type IntoIter = IntoIter<P>;
    type Item = <Self::IntoIter as Iterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        let mut events = self.events;
        events.reverse();

        IntoIter { events, index: 0 }
    }
}

pub(crate) struct IntoIter<P: PublicId> {
    events: Vec<Event<P>>,
    index: usize,
}

impl<P: PublicId> Iterator for IntoIter<P> {
    type Item = (EventIndex, Event<P>);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(event) = self.events.pop() {
            let item = (EventIndex(self.index), event);
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }
}

impl<'a, P: PublicId> IntoIterator for &'a Graph<P> {
    type IntoIter = Iter<'a, P>;
    type Item = <Self::IntoIter as Iterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        Iter {
            events: &self.events,
            index: 0,
        }
    }
}

pub(crate) struct Iter<'a, P: PublicId + 'a> {
    events: &'a [Event<P>],
    index: usize,
}

impl<'a, P: PublicId> Iterator for Iter<'a, P> {
    type Item = IndexedEventRef<'a, P>;

    fn next(&mut self) -> Option<Self::Item> {
        let event = self.events.get(self.index)?;
        let item = IndexedEventRef {
            index: EventIndex(self.index),
            event,
        };
        self.index += 1;
        Some(item)
    }
}

#[cfg(any(all(test, feature = "mock"), feature = "dump-graphs"))]
pub(crate) mod snapshot {
    use super::*;

    /// Snapshot of the graph. Two snapshots compare as equal if the graphs had the same events
    /// modulo their insertion order.
    #[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub(crate) struct GraphSnapshot(BTreeSet<EventHash>);

    impl GraphSnapshot {
        pub fn new<P: PublicId>(graph: &Graph<P>) -> Self {
            GraphSnapshot(graph.iter().map(|event| *event.hash()).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::find_event_by_short_name;
    use crate::dev_utils::parse_test_dot_file;

    #[test]
    fn ancestors_iterator() {
        // Generated with RNG seed: [174994228, 1445633118, 3041276290, 90293447].
        let contents = parse_test_dot_file("carol.dot");
        let graph = contents.graph;

        let event = unwrap!(find_event_by_short_name(&graph, "B_4"));

        let expected = vec![
            "B_4", "B_3", "D_2", "D_1", "D_0", "B_2", "B_1", "B_0", "A_1", "A_0",
        ];

        let mut actual_names = Vec::new();
        let mut actual_indices = Vec::new();

        for event in graph.ancestors(event) {
            actual_names.push(event.short_name().to_string());
            actual_indices.push(event.event_index());
        }

        assert_eq!(actual_names, expected);

        // Assert the events are yielded in reverse topological order.
        let mut sorted_indices = actual_indices.clone();
        sorted_indices.sort_by(|a, b| b.cmp(a));

        assert_eq!(actual_indices, sorted_indices);
    }
}
