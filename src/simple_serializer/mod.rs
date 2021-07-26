// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::usb::end_point::u4;
use dtoa::Floating;
use itoa::Integer;
use serde::ser;
use serde::ser::Serializer;
use serde::ser::SerializeSeq;
use serde::ser::SerializeTuple;
use serde::ser::SerializeTupleVariant;
use serde::ser::SerializeTupleStruct;
use serde::ser::SerializeMap;
use serde::ser::SerializeStructVariant;
use serde::ser::SerializeStruct;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io;
use std::io::BufWriter;
use std::io::Write;
use std::mem::MaybeUninit;
use std::slice::from_raw_parts_mut;
use serde::Serialize;
use swiss_army_knife::get_unchecked::GetUnchecked;
use std::ops::{Deref, DerefMut};


include!("SimpleSerializer.rs");
include!("SimpleSerializerError.rs");
include!("SimpleMapSerializer.rs");
include!("SimpleSequenceSerializer.rs");
include!("SimpleStructSerializer.rs");
