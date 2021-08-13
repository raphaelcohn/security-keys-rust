// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::DeadOrAlive;
use super::DeadOrAlive::Alive;
use super::DeadOrAlive::Dead;
use super::DeviceHandle;
use crate::collections::Bytes;
use crate::collections::VecExt;
use crate::descriptors::DescriptorHeaderLength;
use crate::configuration::MaximumNumberOfConfigurations;
use crate::control_transfers::descriptors::get_binary_object_store_device_descriptor;
use crate::control_transfers::descriptors::GetStandardUsbDescriptorError;
use crate::integers::u1;
use crate::integers::u2;
use crate::integers::u4;
use crate::integers::u11;
use enumflags2::bitflags;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::MaybeUninit;
use std::mem::size_of;
use std::mem::transmute;
use swiss_army_knife::get_unchecked::GetUnchecked;
use uuid::Uuid;
use crate::version::{Version, VersionParseError};
use std::ops::Deref;
use crate::collections::{WrappedIndexSet, WrappedIndexMap, WithCapacity, WrappedHashMap, WrappedBitFlags};


include!("DeviceCapability.rs");
include!("DeviceCapabilityParseError.rs");
include!("BinaryObjectStore.rs");
include!("BinaryObjectStoreBuffer.rs");
include!("BinaryObjectStoreParseError.rs");
include!("BitRate.rs");
include!("ConfigurationSummaryDeviceCapability.rs");
include!("ConfigurationSummaryDeviceCapabilityParseError.rs");
include!("ContainerIdentifierDeviceCapability.rs");
include!("ContainerIdentifierDeviceCapabilityParseError.rs");
include!("PlatformDeviceCapability.rs");
include!("PlatformDeviceCapabilityParseError.rs");
include!("ReceiveOrTransmit.rs");
include!("SublinkProtocol.rs");
include!("SublinkSpeedAttribute.rs");
include!("SublinkSpeedAttributeIdentifier.rs");
include!("SublinkSpeedLinks.rs");
include!("SublinkType.rs");
include!("SublinkTypeSymmetry.rs");
include!("ReservedDeviceCapability.rs");
include!("SuperSpeedDeviceCapability.rs");
include!("SuperSpeedDeviceCapabilityParseError.rs");
include!("SuperSpeedDeviceCapabilitySupportedSpeed.rs");
include!("SuperSpeedPlusDeviceCapability.rs");
include!("SuperSpeedPlusDeviceCapabilityParseError.rs");
include!("Usb2ExtensionDeviceCapability.rs");
include!("Usb2ExtensionDeviceCapabilityParseError.rs");
