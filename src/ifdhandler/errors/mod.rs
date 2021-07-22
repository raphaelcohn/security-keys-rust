// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


use super::c::constants::response_codes::IFD_RESPONSE_TIMEOUT;
use super::c::constants::response_codes::IFD_NOT_SUPPORTED;
use super::c::constants::response_codes::IFD_ICC_PRESENT;
use super::c::constants::response_codes::IFD_ICC_NOT_PRESENT;
use super::c::constants::response_codes::IFD_NO_SUCH_DEVICE;
use super::c::constants::response_codes::IFD_ERROR_TAG;
use super::c::constants::response_codes::IFD_ERROR_SET_FAILURE;
use super::c::constants::response_codes::IFD_ERROR_VALUE_READ_ONLY;
use super::c::constants::response_codes::IFD_ERROR_PTS_FAILURE;
use super::c::constants::response_codes::IFD_ERROR_NOT_SUPPORTED;
use super::c::constants::response_codes::IFD_PROTOCOL_NOT_SUPPORTED;
use super::c::constants::response_codes::IFD_ERROR_POWER_ACTION;
use super::c::constants::response_codes::IFD_ERROR_SWALLOW;
use super::c::constants::response_codes::IFD_ERROR_EJECT;
use super::c::constants::response_codes::IFD_ERROR_CONFISCATE;
use super::c::constants::response_codes::IFD_ERROR_INSUFFICIENT_BUFFER;
use super::c::types::RESPONSECODE;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;


include!("CreateChannelUnexpectedError.rs");
include!("GenericError.rs");
include!("PresenceUnexpectedError.rs");
