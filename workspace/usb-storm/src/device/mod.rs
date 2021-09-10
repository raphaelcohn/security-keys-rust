// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::integers::u3;
use crate::collections::VecExt;
use crate::serde::TryReserveErrorRemote;
use self::binary_object_store::BinaryObjectStore;
use self::binary_object_store::BinaryObjectStoreParseError;
use self::binary_object_store::DeviceCapability;
use self::logical_location::LogicalLocation;
use self::physical_location::PhysicalLocation;
use self::product::Product;
use self::product::ProductIdentifier;
use self::vendor::Vendor;
use self::vendor::VendorIdentifier;
use super::class_and_protocol::DeviceClass;
use super::configuration::Configuration;
use super::configuration::ConfigurationNumber;
use super::configuration::ConfigurationParseError;
use super::configuration::GetConfigurationDescriptorBackendError;
use super::configuration::get_active_config_descriptor;
use super::configuration::get_config_descriptor;
use super::configuration::MaximumNumberOfConfigurations;
use super::interface::InterfaceNumber;
use super::string::GetLanguagesError;
use super::string::GetLocalizedStringError;
use super::string::LocalizedStrings;
use super::string::language::Language;
use super::version::Version;
use super::version::VersionParseError;
use libusb1_sys::libusb_close;
use libusb1_sys::libusb_device;
use libusb1_sys::libusb_device_descriptor;
use libusb1_sys::libusb_device_handle;
use libusb1_sys::libusb_get_device;
use libusb1_sys::libusb_get_device_descriptor;
use libusb1_sys::libusb_get_device_speed;
use libusb1_sys::libusb_get_parent;
use libusb1_sys::libusb_open;
use libusb1_sys::libusb_release_interface;
use libusb1_sys::constants::LIBUSB_ERROR_IO;
use libusb1_sys::constants::LIBUSB_ERROR_INVALID_PARAM;
use libusb1_sys::constants::LIBUSB_ERROR_ACCESS;
use libusb1_sys::constants::LIBUSB_ERROR_NO_DEVICE;
use libusb1_sys::constants::LIBUSB_ERROR_BUSY;
use libusb1_sys::constants::LIBUSB_ERROR_TIMEOUT;
use libusb1_sys::constants::LIBUSB_ERROR_NOT_FOUND;
use libusb1_sys::constants::LIBUSB_ERROR_OVERFLOW;
use libusb1_sys::constants::LIBUSB_ERROR_PIPE;
use libusb1_sys::constants::LIBUSB_ERROR_INTERRUPTED;
use libusb1_sys::constants::LIBUSB_ERROR_NO_MEM;
use libusb1_sys::constants::LIBUSB_ERROR_NOT_SUPPORTED;
use libusb1_sys::constants::LIBUSB_ERROR_OTHER;
use libusb1_sys::constants::LIBUSB_SPEED_FULL;
use libusb1_sys::constants::LIBUSB_SPEED_HIGH;
use libusb1_sys::constants::LIBUSB_SPEED_LOW;
use libusb1_sys::constants::LIBUSB_SPEED_SUPER;
use libusb1_sys::constants::LIBUSB_SPEED_UNKNOWN;
use likely::likely;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::{TryReserveError, BTreeMap};
use std::ops::Deref;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::MaybeUninit;
use std::mem::size_of;
use std::mem::transmute;
use std::ptr::NonNull;
use swiss_army_knife::non_zero::{new_non_null, new_non_zero_u8};
use swiss_army_knife::get_unchecked::GetUnchecked;
use self::DeadOrAlive::Alive;
use self::DeadOrAlive::Dead;
use crate::collections::WrappedIndexMap;
use crate::collections::WithCapacity;
use crate::string::language::LanguageIdentifier;
use std::num::NonZeroU8;
use crate::control_transfers::descriptors::MaximumStandardUsbDescriptorLength;
use crate::string::{GetWebUrlError, get_localized_string_utf16_little_endian, GetLocalizedUtf16LittleEndianStringError};
use crate::string::find_web_usb_url_control_transfer;
use crate::string::WebUrl;
use crate::string::get_languages;
use crate::string::get_localized_string;
use crate::device::hub::HubDescriptor;
use crate::device::hub::HubDescriptorParseError;
use either::Either;
use either::Left;
use either::Right;
use crate::device::logical_location::LocationError;
use crate::device::binary_object_store::platform_device_capability::microsoft_operating_system::MicrosoftOperatingSystemDescriptorSupport;
use crate::device::binary_object_store::platform_device_capability::microsoft_operating_system::MicrosoftVendorCode;
use crate::device::binary_object_store::super_speed_device_capability::SuperSpeedDeviceCapabilitySupportedSpeed;


include!("return_ok_if_dead.rs");
include!("return_ok_if_dead_or_alive_none.rs");


/// Binary Object Store (BOS).
pub mod binary_object_store;


/// Hub descriptors.
pub mod hub;


/// Bus and address.
pub mod logical_location;


/// Port number.
pub mod physical_location;


/// Product details.
pub mod product;


/// USB vendor.
pub mod vendor;


include!("DeadOrAlive.rs");
include!("DeadOrFailedToParseDeviceDetails.rs");
include!("Device.rs");
include!("DeviceConnection.rs");
include!("DeviceHandle.rs");
include!("DeviceHandleOpenError.rs");
include!("DeviceParseError.rs");
include!("DeviceReference.rs");
include!("DeviceReferenceParseError.rs");
include!("get_device.rs");
include!("get_device_descriptor.rs");
include!("get_device_speed.rs");
include!("get_parent.rs");
include!("ListDevicesError.rs");
include!("Location.rs");
include!("ReusableBuffer.rs");
include!("Speed.rs");
