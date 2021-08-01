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


#![feature(allocator_api)]
#![feature(arbitrary_enum_discriminant)]
#![feature(associated_type_bounds)]
#![feature(const_ptr_is_null)]
#![feature(core_intrinsics)]
#![feature(macro_attributes_in_derive_output)]
#![feature(maybe_uninit_slice)]
#![feature(maybe_uninit_uninit_array)]
#![feature(once_cell)]
#![feature(slice_ptr_get)]
#![feature(slice_ptr_len)]
#![feature(try_reserve)]


//! usb-storm is a library for enumerating USB devices and parsing USB descriptors.


use clap as _;
use ron as _;
use serde_lexpr as _;
use serde_yaml as _;


use self::device::ProductIdentifier;
use self::device::VendorIdentifier;
use self::version::Version;
use std::collections::HashMap;
use std::collections::TryReserveError;
use std::fmt::Debug;
use std::hash::Hash;
use std::num::NonZeroU8;
use swiss_army_knife::non_zero::new_non_zero_u8;


/// Additional descriptors, eg for Smart Cards and Human Interface Devices (HID).
pub mod additional_descriptors;


/// Class, sub-class and protocol.
pub mod class_and_protocol;


/// libusb context.
pub mod context;


/// USB configuration.
pub mod configuration;


/// Transfers.
pub mod control_transfers;


/// Device.
pub mod device;


/// USB end points.
pub mod end_point;


/// USB interfaces.
pub mod interface;


/// A simple serializer for dumping data to the console.
pub mod simple_serializer;


/// USB strings.
pub mod string;


/// USB binary coded decimal version.
pub mod version;


include!("DeviceInformationDatabase.rs");
include!("FixedUsbDeviceCapabilities.rs");
include!("VecExt.rs");
include!("u3.rs");
include!("u4.rs");
include!("u5.rs");
include!("u6.rs");
include!("u11.rs");
