// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


use super::card_state::CardReaderStates;
use super::c::constants::MAX_READERNAME;
use super::c::constants::PCSCLITE_MAX_READERS_CONTEXTS;
use super::c::fundamental_types::DWORD;
use super::errors::CardReaderNameError;
use arrayvec::ArrayVec;
use libc::c_char;
use likely::likely;
use likely::unlikely;
use memchr::memchr;
use std::borrow::Borrow;
use std::borrow::Cow;
use std::convert::TryFrom;
use std::ffi::CStr;
use std::ffi::CString;
use std::ops::Deref;
use swiss_army_knife::get_unchecked::GetUnchecked;


include!("CardReaderEventName.rs");
include!("CardReaderName.rs");
include!("CardReaderNames.rs");
include!("CardReaderNamesBuffer.rs");
include!("CardReaderNamesBufferMaximumSize.rs");
include!("CardReaderNamesIterator.rs");
