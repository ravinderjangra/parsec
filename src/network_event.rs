// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, hash::Hash};

/// This represents the type which will be voted for by peers; generally it is the set of
/// constraints on `T` throughout this library.
pub trait NetworkEvent:
    Clone + Eq + Ord + PartialEq + PartialOrd + Hash + Serialize + DeserializeOwned + Debug
{
}
