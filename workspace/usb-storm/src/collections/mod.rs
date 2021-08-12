// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use enumflags2::{BitFlag, FromBitsError};
use enumflags2::BitFlags;
use indexmap::map::IndexMap;
use indexmap::set::IndexSet;
use serde::{Deserialize, Serializer, Deserializer};
use serde::Serialize;
use std::cmp::min;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::TryReserveError;
use std::hash::Hash;
use std::hash::Hasher;
use std::ops::Deref;
use std::ops::DerefMut;
use swiss_army_knife::get_unchecked::AsUsizeIndex;
use serde::de::{Error, Unexpected};


include!("WithCapacity.rs");
include!("WrappedBitFlags.rs");
include!("WrappedHashMap.rs");
include!("WrappedHashSet.rs");
include!("WrappedIndexMap.rs");
include!("WrappedIndexSet.rs");
