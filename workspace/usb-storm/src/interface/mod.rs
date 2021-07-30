// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::u5;
use crate::VecExt;
use super::version::Version;
use self::human_interface_device::HumanInterfaceDeviceInterfaceAdditionalDescriptor;
use self::human_interface_device::HumanInterfaceDeviceInterfaceAdditionalDescriptorParseError;
use self::human_interface_device::HumanInterfaceDeviceInterfaceAdditionalDescriptorParser;
use self::human_interface_device::HumanInterfaceDeviceInterfaceAdditionalVariant;
use self::smart_card::SmartCardInterfaceAdditionalDescriptor;
use self::smart_card::SmartCardInterfaceAdditionalDescriptorParser;
use self::smart_card::SmartCardInterfaceAdditionalDescriptorParseError;
use self::unsupported::UnsupportedInterfaceAdditionalDescriptor;
use self::unsupported::UnsupportedInterfaceAdditionalDescriptorParser;
use super::additional_descriptors::AdditionalDescriptor;
use super::additional_descriptors::AdditionalDescriptorParseError;
use super::additional_descriptors::AdditionalDescriptorParser;
use super::additional_descriptors::DescriptorType;
use super::additional_descriptors::extra_to_slice;
use super::additional_descriptors::parse_additional_descriptors;
use super::class_and_protocol::ClassAndProtocol;
use super::class_and_protocol::DeviceOrAlternateSetting;
use super::end_point::EndPoint;
use super::end_point::EndPointNumber;
use super::end_point::InclusiveMaximumNumberOfEndPoints;
use super::errors::UsbError;
use super::string::StringFinder;
use super::string::StringOrIndex;
use indexmap::map::IndexMap;
use libusb1_sys::{libusb_interface_descriptor, libusb_endpoint_descriptor};
use libusb1_sys::libusb_config_descriptor;
use libusb1_sys::libusb_interface;
use libusb1_sys::constants::LIBUSB_DT_INTERFACE;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::convert::Infallible;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::transmute;
use std::num::NonZeroU8;
use std::slice::from_raw_parts;
use swiss_army_knife::get_unchecked::GetUnchecked;
use swiss_army_knife::non_zero::new_non_zero_u8;
use crate::end_point::EndPointParseError;


/// CCID (Chip Card Interface Device).
pub mod smart_card;


/// Human Interface Device (HID).
pub mod human_interface_device;


/// Unsupported.
pub(crate) mod unsupported;


include!("AlternateSetting.rs");
include!("AlternateSettingNumber.rs");
include!("AlternateSettingParseError.rs");
include!("Bytes.rs");
include!("Interface.rs");
include!("InterfaceAdditionalDescriptor.rs");
include!("InterfaceAdditionalDescriptorParseError.rs");
include!("InterfaceAdditionalDescriptorParser.rs");
include!("InterfaceNumber.rs");
include!("InterfaceParseError.rs");
include!("MaximumNumberOfAlternateSettings.rs");
include!("MaximumNumberOfInterfaces.rs");
include!("adjust_index.rs");
