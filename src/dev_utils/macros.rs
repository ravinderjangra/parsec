// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(all(test, feature = "mock"))]
macro_rules! btree_set {
    () => {
        BTreeSet::new()
    };

    ($($item:expr),*) => {{
        let mut set = BTreeSet::new();
        $(
            let _ = set.insert($item);
        )*
        set
    }}
}

#[cfg(test)]
macro_rules! btree_map {
    () => {
        BTreeMap::new()
    };

    ($($key:expr => $value:expr),*) => {{
        let mut map = BTreeMap::new();
        $(
            let _ = map.insert($key, $value);
        )*
        map
    }}
}
