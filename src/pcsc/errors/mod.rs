// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::AttributeIdentifier;
use super::CardDisposition;
use super::Scope;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::ffi::NulError;


include!("ActivityError.rs");
include!("CardCommandError.rs");
include!("CardReaderNameError.rs");
include!("CardReaderStatusChangeError.rs");
include!("CardStatusError.rs");
include!("CardTransmissionError.rs");
include!("CommunicationError.rs");
include!("ConnectCardError.rs");
include!("ReconnectionUnavailableOrCommunicationError.rs");
include!("TransactionError.rs");
include!("UnavailableError.rs");
include!("UnavailableOrCommunicationError.rs");
include!("WithDisconnectError.rs");
