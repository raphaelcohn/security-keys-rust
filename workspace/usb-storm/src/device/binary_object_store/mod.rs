// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::DeadOrAlive;
use super::DeadOrAlive::Alive;
use super::DeadOrAlive::Dead;
use crate::collections::Bytes;
use crate::collections::VecExt;
use crate::descriptors::DescriptorHeaderLength;
use crate::configuration::MaximumNumberOfConfigurations;
use crate::control_transfers::descriptors::get_binary_object_store_device_descriptor;
use crate::control_transfers::descriptors::GetStandardUsbDescriptorError;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use swiss_army_knife::get_unchecked::GetUnchecked;
use crate::version::Version;
use crate::version::VersionParseError;
use std::ops::Deref;
use crate::collections::WrappedIndexSet;
use crate::collections::WithCapacity;
use crate::class_and_protocol::FunctionClass;
use crate::class_and_protocol::FunctionClassParseError;
use crate::device::DeviceConnection;
use crate::device::ReusableBuffer;
use crate::serde::TryReserveErrorRemote;
use crate::universally_unique_identifiers_support::UniversallyUniqueIdentifier;
use crate::device::binary_object_store::super_speed_device_capability::SuperSpeedPlusDeviceCapability;
use crate::device::binary_object_store::super_speed_device_capability::SuperSpeedDeviceCapability;
use crate::device::binary_object_store::super_speed_device_capability::SuperSpeedDeviceCapabilityParseError;
use crate::device::binary_object_store::super_speed_device_capability::SuperSpeedPlusDeviceCapabilityParseError;
use crate::device::binary_object_store::platform_device_capability::PlatformDeviceCapability;
use crate::device::binary_object_store::platform_device_capability::PlatformDeviceCapabilityParseError;
use crate::device::binary_object_store::billboard::BillboardDeviceCapability;
use crate::device::binary_object_store::billboard::BillboardAlternateModeDeviceCapability;
use crate::device::binary_object_store::billboard::BillboardDeviceCapabilityParseError;
use crate::device::binary_object_store::billboard::BillboardAlternateModeDeviceCapabilityParseError;


/// Billboard.
pub mod billboard;


/// Platform device capability
pub mod platform_device_capability;


/// Super speed device capability.
pub mod super_speed_device_capability;


include!("BinaryObjectStore.rs");include!("BinaryObjectStoreParseError.rs");
include!("capability_descriptor_index.rs");
include!("ConfigurationSummaryDeviceCapability.rs");
include!("ConfigurationSummaryDeviceCapabilityParseError.rs");
include!("ContainerIdentifierDeviceCapability.rs");
include!("ContainerIdentifierDeviceCapabilityParseError.rs");
include!("DeviceCapability.rs");
include!("DeviceCapabilityParseError.rs");
include!("minimum_size.rs");
include!("ReservedDeviceCapability.rs");
include!("Usb2ExtensionDeviceCapability.rs");
include!("Usb2ExtensionDeviceCapabilityParseError.rs");
