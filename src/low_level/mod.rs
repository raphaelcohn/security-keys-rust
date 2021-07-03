// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use self::transmit::ApplicationProtocolDataUnitCommand;
use self::transmit::CommandChaining;
use self::transmit::ReceiveBuffers;
use self::transmit::Response;
use self::transmit::ResponseLengthEncoding;
use self::transmit::SendBuffer;
use self::transmit::response_code::ResponseCode;
use self::transmit::response_code::ClassFunctionError;
use self::transmit::response_code::StateOfNonVolatileMemoryUnchangedWarning;
use likely::unlikely;
use pcsc::{Attribute, CardStatus};
use pcsc::Card;
use pcsc::Context;
use pcsc::Disposition;
use pcsc::MAX_BUFFER_SIZE_EXTENDED;
use pcsc::Protocol;
use pcsc::Protocols;
use pcsc::ReaderNames;
use pcsc::Scope;
use pcsc::ShareMode;
use pcsc::Transaction;
use std::collections::TryReserveError;
use std::fmt;
use std::error;
use std::ffi::CStr;
use std::fmt::{Display, Debug};
use std::fmt::Formatter;
use std::num::NonZeroU16;
use std::ops::Deref;
use std::string::ToString;


mod transmit;



include!("ActivityError.rs");
include!("AnswerToReset.rs");
include!("CardError.rs");
include!("CardExt.rs");
include!("CardOrTransactionExt.rs");
include!("ContextError.rs");
include!("ContextExt.rs");
include!("VecExt.rs");

