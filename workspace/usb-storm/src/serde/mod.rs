// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use serde::Deserialize;
use serde::Serialize;
use std::alloc::AllocError;
use std::alloc::Layout;
use std::char::DecodeUtf16Error;
use std::collections::TryReserveError;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::num::NonZeroUsize;
use std::mem::transmute;
use std::string::FromUtf8Error;
use std::str::Utf8Error;
use swiss_army_knife::non_zero::new_non_zero_usize;


include!("AllocErrorRemote.rs");
include!("DecodeUtf16ErrorRemote.rs");
include!("FromUtf8ErrorRemote.rs");
include!("InfallibleError.rs");
include!("LayoutRemote.rs");
include!("TryReserveErrorRemote.rs");
include!("Utf8ErrorRemote.rs");
