// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![deny(absolute_paths_not_starting_with_crate)]
#![deny(invalid_html_tags)]
#![deny(macro_use_extern_crate)]
#![deny(missing_crate_level_docs)]
#![deny(missing_docs)]
#![deny(pointer_structural_match)]
#![deny(unaligned_references)]
#![deny(unconditional_recursion)]
#![deny(unreachable_patterns)]
#![deny(unused_import_braces)]
#![deny(unused_must_use)]
#![deny(unused_qualifications)]
#![deny(unused_results)]
#![warn(unreachable_pub)]
#![warn(unused_lifetimes)]
#![warn(unused_crate_dependencies)]


#![feature(arbitrary_enum_discriminant)]
#![feature(associated_type_bounds)]
#![feature(core_intrinsics)]
#![feature(macro_attributes_in_derive_output)]
#![feature(maybe_uninit_uninit_array)]
#![feature(try_reserve)]


//! usb-storm is a library for enumerating USB devices and parsing USB descriptors.


use clap as _;
use ron as _;
use serde_lexpr as _;
use serde_yaml as _;


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
use std::collections::TryReserveError;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::hash::Hash;
use std::hash::Hasher;
use std::num::NonZeroU8;
use std::time::Duration;
use swiss_army_knife::non_zero::new_non_zero_u8;


/// Additional descriptors, eg for Smart Cards and Human Interface Devices (HID).
pub mod additional_descriptors;


/// Class, sub-class and protocol.
pub mod class_and_protocol;


/// USB configuration.
pub mod configuration;


/// USB end points.
pub(crate) mod end_point;


/// Errors.
pub mod errors;


/// USB interfaces.
pub mod interface;


/// USB language.
pub mod language;


/// A simple serializer for dumping data to the console.
pub mod simple_serializer;


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
include!("VecExt.rs");
