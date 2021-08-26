// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use self::interface_association::InterfaceAssociationConfigurationExtraDescriptor;
use self::interface_association::InterfaceAssociationConfigurationExtraDescriptorParseError;
use self::interface_association::InterfaceAssociationConfigurationExtraDescriptorParser;
use super::integers::u3;
use super::integers::u5;
use super::descriptors::DescriptorParseError;
use super::descriptors::DescriptorParser;
use super::descriptors::DescriptorType;
use super::descriptors::extra_to_slice;
use super::descriptors::parse_descriptors;
use super::control_transfers::ControlTransferError;
use super::device::Speed;
use super::interface::Interface;
use super::interface::InterfaceNumber;
use super::interface::InterfaceParseError;
use super::interface::MaximumNumberOfInterfaces;
use super::string::GetLocalizedStringError;
use super::string::LocalizedStrings;
use super::string::StringFinder;
use super::version::Version;
use libusb1_sys::constants::LIBUSB_DT_CONFIG;
use libusb1_sys::constants::LIBUSB_ERROR_ACCESS;
use libusb1_sys::constants::LIBUSB_ERROR_BUSY;
use libusb1_sys::constants::LIBUSB_ERROR_INTERRUPTED;
use libusb1_sys::constants::LIBUSB_ERROR_INVALID_PARAM;
use libusb1_sys::constants::LIBUSB_ERROR_IO;
use libusb1_sys::constants::LIBUSB_ERROR_NOT_FOUND;
use libusb1_sys::constants::LIBUSB_ERROR_NOT_SUPPORTED;
use libusb1_sys::constants::LIBUSB_ERROR_NO_DEVICE;
use libusb1_sys::constants::LIBUSB_ERROR_NO_MEM;
use libusb1_sys::constants::LIBUSB_ERROR_OTHER;
use libusb1_sys::constants::LIBUSB_ERROR_OVERFLOW;
use libusb1_sys::constants::LIBUSB_ERROR_PIPE;
use libusb1_sys::constants::LIBUSB_ERROR_TIMEOUT;
use libusb1_sys::libusb_config_descriptor;
use libusb1_sys::libusb_device;
use libusb1_sys::libusb_device_handle;
use libusb1_sys::libusb_free_config_descriptor;
use libusb1_sys::libusb_get_active_config_descriptor;
use libusb1_sys::libusb_get_config_descriptor;
use libusb1_sys::libusb_get_configuration;
use libusb1_sys::libusb_interface;
use likely::likely;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::mem::MaybeUninit;
use std::mem::transmute;
use std::num::NonZeroU16;
use std::num::NonZeroU8;
use std::ops::Deref;
use std::ptr::NonNull;
use std::slice::from_raw_parts;
use swiss_army_knife::get_unchecked::GetUnchecked;
use swiss_army_knife::non_zero::new_non_null;
use swiss_army_knife::non_zero::new_non_zero_u16;
use swiss_army_knife::non_zero::new_non_zero_u8;
use crate::device::DeadOrAlive;
use crate::device::DeadOrAlive::{Alive, Dead};
use crate::collections::{WrappedIndexMap, WithCapacity};
use std::collections::TryReserveError;


/// Interface association descriptor (IAD).
pub mod interface_association;


include!("Configuration.rs");
include!("ConfigurationAttributes.rs");
include!("ConfigurationDescriptor.rs");
include!("ConfigurationExtraDescriptor.rs");
include!("ConfigurationExtraDescriptorParser.rs");
include!("ConfigurationExtraDescriptorParseError.rs");
include!("ConfigurationNumber.rs");
include!("ConfigurationParseError.rs");
include!("get_active_config_descriptor.rs");
include!("get_config_descriptor.rs");
include!("get_configuration.rs");
include!("GetConfigurationDescriptorBackendError.rs");
include!("MaximumNumberOfConfigurations.rs");
include!("MaximumPowerConsumption.rs");
include!("MaximumPowerConsumptionMilliamps.rs");
