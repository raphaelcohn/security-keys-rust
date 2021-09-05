// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::collections::VecExt;
use crate::collections::WrappedBitFlags;
use crate::descriptors::DescriptorHeaderLength;
use crate::descriptors::DescriptorParser;
use crate::descriptors::DescriptorType;
use crate::descriptors::descriptor_index;
use crate::descriptors::verify_remaining_bytes;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive::Dead;
use crate::device::DeadOrAlive;
use crate::device::DeviceConnection;
use crate::serde::TryReserveErrorRemote;
use crate::string::GetLocalizedStringError;
use crate::string::LocalizedStrings;
use crate::string::language::EnglishSubLanguage;
use crate::string::language::HumanInterfaceDeviceSubLanguage;
use crate::string::language::Language;
use enumflags2::bitflags;
use likely::likely;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::num::NonZeroU8;
use std::str::Split;
use strum::IntoEnumIterator;
use swiss_army_knife::get_unchecked::GetUnchecked;
use swiss_army_knife::non_zero::new_non_zero_u8;


include!("Authentication.rs");
include!("BasicCapability.rs");
include!("InternetPrintingProtocolInterfaceExtraDescriptor.rs");
include!("InternetPrintingProtocolInterfaceExtraDescriptorParseError.rs");
include!("InternetPrintingProtocolInterfaceExtraDescriptorParser.rs");
include!("VendorCapabilityDescriptor.rs");
