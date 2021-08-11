// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::integers::u5;
use self::device_firmware_upgrade::DeviceFirmwareUpgradeInterfaceAdditionalDescriptor;
use self::device_firmware_upgrade::DeviceFirmwareUpgradeInterfaceAdditionalDescriptorParseError;
use self::device_firmware_upgrade::DeviceFirmwareUpgradeInterfaceAdditionalDescriptorParser;
use self::human_interface_device::HumanInterfaceDeviceInterfaceAdditionalDescriptor;
use self::human_interface_device::HumanInterfaceDeviceInterfaceAdditionalDescriptorParseError;
use self::human_interface_device::HumanInterfaceDeviceInterfaceAdditionalDescriptorParser;
use self::human_interface_device::HumanInterfaceDeviceInterfaceAdditionalVariant;
use self::smart_card::SmartCardInterfaceAdditionalDescriptor;
use self::smart_card::SmartCardInterfaceAdditionalDescriptorParseError;
use self::unsupported::UnsupportedInterfaceAdditionalDescriptor;
use super::additional_descriptors::AdditionalDescriptor;
use super::additional_descriptors::AdditionalDescriptorParseError;
use super::additional_descriptors::AdditionalDescriptorParser;
use super::additional_descriptors::DescriptorType;
use super::additional_descriptors::extra_to_slice;
use super::additional_descriptors::parse_additional_descriptors;
use super::class_and_protocol::ApplicationSpecificInterfaceSubClass;
use super::class_and_protocol::HumanInterfaceDeviceInterfaceBootProtocol;
use super::class_and_protocol::HumanInterfaceDeviceInterfaceSubClass;
use super::class_and_protocol::InterfaceClass;
use super::class_and_protocol::KnownOrUnrecognizedProtocol;
use super::class_and_protocol::SmartCardProtocol;
use super::class_and_protocol::SmartCardInterfaceSubClass;
use super::class_and_protocol::UnrecognizedSubClass;
use super::device::DeadOrAlive;
use super::end_point::EndPoint;
use super::end_point::EndPointNumber;
use super::end_point::EndPointParseError;
use super::end_point::InclusiveMaximumNumberOfEndPoints;
use super::interface::smart_card::SmartCardInterfaceAdditionalDescriptorParser;
use super::interface::unsupported::UnsupportedInterfaceAdditionalDescriptorParser;
use super::string::GetLocalizedStringError;
use super::string::LocalizedStrings;
use super::string::StringFinder;
use libusb1_sys::libusb_endpoint_descriptor;
use libusb1_sys::libusb_interface;
use libusb1_sys::libusb_interface_descriptor;
use libusb1_sys::constants::LIBUSB_DT_INTERFACE;
use indexmap::map::IndexMap;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::convert::Infallible;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::num::NonZeroU8;
use std::ptr::NonNull;
use std::slice::from_raw_parts;
use swiss_army_knife::get_unchecked::GetUnchecked;
use swiss_army_knife::non_zero::new_non_zero_u8;
use crate::version::Version;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive::Dead;


/// Audio.
pub mod audio;


/// Device Firmware Upgrade (DFU).
pub mod device_firmware_upgrade;


/// Human Interface Device (HID).
pub mod human_interface_device;


/// CCID (Chip Card Interface Device).
pub mod smart_card;


/// Unsupported.
pub(crate) mod unsupported;


include!("AlternateSetting.rs");
include!("AlternateSettingNumber.rs");
include!("AlternateSettingParseError.rs");
include!("Interface.rs");
include!("InterfaceAdditionalDescriptor.rs");
include!("InterfaceAdditionalDescriptorParseError.rs");
include!("InterfaceAdditionalDescriptorParser.rs");
include!("InterfaceNumber.rs");
include!("InterfaceParseError.rs");
include!("MaximumNumberOfAlternateSettings.rs");
include!("MaximumNumberOfInterfaces.rs");
