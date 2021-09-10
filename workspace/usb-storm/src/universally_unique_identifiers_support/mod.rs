// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use arrayvec::ArrayString;
use arrayvec::ArrayVec;
use crate::integers::u14;
use crate::integers::u4;
use crate::integers::u60;
use likely::unlikely;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde::de::Visitor;
use serde::de;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::mem::size_of;
use std::mem::transmute;
use std::panic::catch_unwind;
use swiss_army_knife::get_unchecked::GetUnchecked;


include!("Variant.rs");
include!("MicrosoftUniversallyUniqueIdentifierStringParser.rs");
include!("UniversallyUniqueIdentifier.rs");
include!("UniversallyUniqueIdentifierStringParser.rs");
