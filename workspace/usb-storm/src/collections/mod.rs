// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::version::Version;
use crate::version::VersionParseError;
use enumflags2::BitFlag;
use enumflags2::BitFlags;
use enumflags2::FromBitsError;
use indexmap::map::IndexMap;
use indexmap::set::IndexSet;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde::de::Visitor;
use serde::de::SeqAccess;
use std::cmp::Ordering;
use std::cmp::min;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::TryReserveError;
use std::error;
use std::fmt;
use std::hash::Hash;
use std::hash::Hasher;
use std::marker::PhantomData;
use std::mem::transmute;
use std::mem::MaybeUninit;
use std::num::NonZeroU8;
use std::num::NonZeroU16;
use std::ops::Deref;
use std::ops::DerefMut;
use std::ptr::write;
use swiss_army_knife::get_unchecked::AsUsizeIndex;
use swiss_army_knife::get_unchecked::GetUnchecked;
use uuid::Uuid;
use std::fmt::Formatter;
use serde::ser::SerializeSeq;
use crate::integers::u24;


include!("Bytes.rs");
include!("TryClone.rs");
include!("WithCapacity.rs");
include!("WrappedBitFlags.rs");
include!("WrappedHashMap.rs");
include!("WrappedHashSet.rs");
include!("WrappedIndexMap.rs");
include!("WrappedIndexSet.rs");
include!("VecExt.rs");
