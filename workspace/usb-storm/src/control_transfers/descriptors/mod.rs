// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::additional_descriptors::DescriptorType;
use crate::device::DeadOrAlive;
use crate::end_point::transfer_type::Direction;
use crate::interface::InterfaceNumber;
use super::control_transfer;
use super::ControlTransferError;
use super::ControlTransferRecipient;
use super::ControlTransferRequestType;
use super::Request;
use libusb1_sys::libusb_device_handle;
use libusb1_sys::constants::LIBUSB_DT_BOS;
use libusb1_sys::constants::LIBUSB_DT_PHYSICAL;
use libusb1_sys::constants::LIBUSB_DT_REPORT;
use libusb1_sys::constants::LIBUSB_DT_STRING;
use libusb1_sys::constants::LIBUSB_DT_HUB;
use likely::unlikely;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::mem::{MaybeUninit, transmute};
use std::ptr::NonNull;
use std::time::Duration;
use swiss_army_knife::get_unchecked::GetUnchecked;
use std::num::{NonZeroU8, NonZeroI32};
use swiss_army_knife::non_zero::new_non_zero_i32;

include!("get_binary_object_store_device_descriptor.rs");
include!("get_class_device_descriptor.rs");
include!("get_descriptor.rs");
include!("get_device_descriptor.rs");
include!("get_hub_device_descriptor.rs");
include!("get_human_interface_device_physical_interface_descriptor.rs");
include!("get_human_interface_device_physical_interface_descriptor_set.rs");
include!("get_human_interface_device_physical_interface_descriptor_set_sizes.rs");
include!("get_human_interface_device_report_interface_descriptor.rs");
include!("get_interface_descriptor.rs");
include!("get_standard_device_descriptor.rs");
include!("get_standard_interface_descriptor.rs");
include!("get_string_device_descriptor.rs");
include!("get_string_device_descriptor_language.rs");
include!("get_string_device_descriptor_languages.rs");
include!("GetDescriptorError.rs");
include!("GetStandardUsbDescriptorError.rs");
include!("MaximumStandardUsbDescriptorLength.rs");
include!("MinimumStandardUsbDescriptorLength.rs");
include!("StandardUsbDescriptorError.rs");
