// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::VecExt;
use self::language::Language;
use self::language::LanguageIdentifier;
use super::control_transfers::descriptors::get_string_device_descriptor_language;
use super::control_transfers::descriptors::get_string_device_descriptor_languages;
use super::control_transfers::descriptors::GetStandardUsbDescriptorError;
use super::device::DeadOrAlive;
use super::device::DeviceHandle;
use likely::likely;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::collections::TryReserveError;
use std::char::decode_utf16;
use std::char::DecodeUtf16Error;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::MaybeUninit;
use std::num::NonZeroU8;
use std::ops::Deref;
use std::slice::from_raw_parts;
use swiss_army_knife::get_unchecked::GetUnchecked;
use swiss_army_knife::non_zero::new_non_zero_u8;


/// USB language.
pub mod language;


include!("GetLanguagesError.rs");
include!("GetLocalizedStringError.rs");
include!("StringFinder.rs");
include!("LocalizedStrings.rs");
