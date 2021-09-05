// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::collections::TryClone;
use crate::collections::VecExt;
use crate::collections::WithCapacity;
use crate::collections::WrappedHashSet;
use crate::control_transfers::ControlTransferRecipient;
use crate::control_transfers::ControlTransferRequestType;
use crate::control_transfers::control_transfer_in;
use crate::control_transfers::descriptors::GetDescriptorError;
use crate::control_transfers::descriptors::StandardUsbDescriptorError;
use crate::control_transfers::descriptors::get_string_device_descriptor_language;
use crate::control_transfers::descriptors::get_string_device_descriptor_languages;
use crate::descriptors::DescriptorHeaderLength;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive::Dead;
use crate::device::DeadOrAlive;
use crate::serde::DecodeUtf16ErrorRemote;
use crate::serde::FromUtf8ErrorRemote;
use crate::serde::TryReserveErrorRemote;
use crate::string::language::LanguageIdentifier;
use libusb1_sys::libusb_device_handle;
use likely::likely;
use likely::unlikely;
use self::language::Language;
use serde::Deserialize;
use serde::Serialize;
use std::char::DecodeUtf16Error;
use std::char::decode_utf16;
use std::collections::BTreeMap;
use std::collections::TryReserveError;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::mem::MaybeUninit;
use std::num::NonZeroU8;
use std::ops::Deref;
use std::ptr::NonNull;
use std::slice::from_raw_parts;
use std::string::FromUtf8Error;
use super::control_transfers::descriptors::GetStandardUsbDescriptorError;
use swiss_army_knife::get_unchecked::GetUnchecked;


/// USB language.
pub mod language;


include!("encode_utf8_raw.rs");
include!("find_web_usb_url_control_transfer.rs");
include!("get_languages.rs");
include!("get_localized_string.rs");
include!("GetLanguagesError.rs");
include!("GetLocalizedStringError.rs");
include!("GetWebUrlError.rs");
include!("LocalizedStrings.rs");
include!("WebUrl.rs");
include!("WebUrlScheme.rs");
