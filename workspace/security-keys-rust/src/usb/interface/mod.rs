// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::VecExt;
use self::human_interface_device::HumanInterfaceDeviceInterfaceAdditionalDescriptor;
use self::human_interface_device::HumanInterfaceDeviceInterfaceAdditionalDescriptorParseError;
use self::human_interface_device::HumanInterfaceDeviceInterfaceAdditionalDescriptorParser;
use self::human_interface_device::HumanInterfaceDeviceInterfaceAdditionalVariant;
use self::smart_card::SmartCardInterfaceAdditionalDescriptor;
use self::smart_card::SmartCardInterfaceAdditionalDescriptorParser;
use self::smart_card::SmartCardInterfaceAdditionalDescriptorParseError;
use self::unsupported::UnsupportedInterfaceAdditionalDescriptor;
use self::unsupported::UnsupportedInterfaceAdditionalDescriptorParser;
use super::UsbStringFinder;
use super::UsbStringOrIndex;
use super::additional_descriptors::AdditionalDescriptor;
use super::additional_descriptors::AdditionalDescriptorParseError;
use super::additional_descriptors::AdditionalDescriptorParser;
use super::additional_descriptors::DescriptorType;
use super::additional_descriptors::parse_additional_descriptors;
use super::class_and_protocol::DeviceOrInterface;
use super::class_and_protocol::Interface;
use super::class_and_protocol::UsbClassAndProtocol;
use super::end_point::UsbEndPoint;
use super::end_point::EndPointNumber;
use super::errors::UsbError;
use indexmap::map::IndexMap;
use likely::unlikely;
use rusb::ConfigDescriptor;
use rusb::InterfaceDescriptor;
use rusb::UsbContext;
use serde::Deserialize;
use serde::Serialize;
use std::convert::Infallible;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::transmute;
use swiss_army_knife::get_unchecked::GetUnchecked;


/// CCID (Chip Card Interface Device).
pub(crate) mod smart_card;


/// Human Interface Device (HID).
pub(crate) mod human_interface_device;


/// Unsupported.
pub(crate) mod unsupported;


include!("InterfaceAdditionalDescriptor.rs");
include!("InterfaceAdditionalDescriptorParseError.rs");
include!("InterfaceAdditionalDescriptorParser.rs");
include!("UsbInterface.rs");
include!("UsbInterfaceAlternateSetting.rs");
