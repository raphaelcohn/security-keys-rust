// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


use self::class_and_protocol::Device;
use self::class_and_protocol::UsbClassAndProtocol;
use self::configuration::ConfigurationNumber;
use self::configuration::UsbConfiguration;
use self::errors::UsbDeviceError;
use self::errors::UsbError;
use self::interface::smart_card::SmartCardInterfaceAdditionalDescriptor;
use self::language::UsbLanguage;
use rusb::DeviceHandle;
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
use std::fmt::Debug;
use std::hash::Hash;
use std::hash::Hasher;
use std::num::NonZeroU8;
use std::time::Duration;
use swiss_army_knife::non_zero::new_non_zero_u8;


pub(crate) mod additional_descriptors;


/// Class, sub-class and protocol.
pub(crate) mod class_and_protocol;


pub(crate) mod configuration;


/// End points.
pub(crate) mod end_point;


/// Errors.
pub mod errors;


/// Interfaces.
pub(crate) mod interface;


/// Language.
pub mod language;


include!("FixedUsbDeviceCapabilities.rs");
include!("UsbDevice.rs");
include!("UsbDeviceInformationDatabase.rs");
include!("UsbProductIdentifier.rs");
include!("UsbSpeed.rs");
include!("UsbString.rs");
include!("UsbStringFinder.rs");
include!("UsbStringOrIndex.rs");
include!("UsbVendorIdentifier.rs");
include!("UsbVersion.rs");
