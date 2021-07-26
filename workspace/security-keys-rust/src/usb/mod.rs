// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


use self::ccid_device_descriptor::CcidDeviceDescriptor;
use self::ccid_device_descriptor::CcidProtocol;
use self::class_and_protocol::Device;
use self::class_and_protocol::Interface;
use self::class_and_protocol::UsbClassAndProtocol;
use self::end_point::u4;
use self::end_point::UsbEndPoint;
use self::language::UsbLanguage;
use indexmap::map::IndexMap;
use rusb::ConfigDescriptor;
use rusb::DeviceDescriptor;
use rusb::DeviceHandle;
use rusb::InterfaceDescriptor;
use rusb::Language;
use rusb::Speed;
use rusb::UsbContext;
use rusb::Version;
use rusb::devices;
use serde::Deserialize;
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::hash::Hash;
use std::hash::Hasher;
use std::mem::transmute;
use std::num::NonZeroU8;
use std::time::Duration;
use swiss_army_knife::get_unchecked::GetUnchecked;
use swiss_army_knife::non_zero::new_non_zero_u8;


/// CCID (Chip Card Interface Device).
pub(crate) mod ccid_device_descriptor;


/// Class, sub-class and protocol.
pub(crate) mod class_and_protocol;


/// End points.
pub(crate) mod end_point;


/// Language.
pub mod language;


include!("FixedUsbDeviceCapabilities.rs");
include!("UsbConfiguration.rs");
include!("UsbDevice.rs");
include!("UsbDeviceError.rs");
include!("UsbDeviceInformationDatabase.rs");
include!("UsbError.rs");
include!("UsbInterface.rs");
include!("UsbInterfaceAlternateSetting.rs");
include!("UsbProductIdentifier.rs");
include!("UsbSpeed.rs");
include!("UsbString.rs");
include!("UsbStringFinder.rs");
include!("UsbStringOrIndex.rs");
include!("UsbVendorIdentifier.rs");
include!("UsbVersion.rs");
