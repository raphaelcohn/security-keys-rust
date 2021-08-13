// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


use self::response_code::ResponseCode;
use super::CardError;
use super::CardOrTransactionExt;
use crate::collections::VecExt;
use crate::open_pgp::ApplicationIdentifier;
use crate::open_pgp::Sex;
use likely::unlikely;
use std::borrow::Cow;
use std::collections::TryReserveError;
#[allow(deprecated)] use std::mem::uninitialized;
use std::num::NonZeroU16;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::ops::DerefMut;


pub(super) mod response_code;


include!("ApplicationProtocolDataUnitCommand.rs");
include!("CommandChaining.rs");
include!("ReceiveBuffers.rs");
include!("Response.rs");
include!("ResponseLengthEncoding.rs");
include!("SendBuffer.rs");
