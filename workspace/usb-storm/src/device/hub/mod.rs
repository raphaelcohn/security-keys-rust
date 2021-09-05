// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::{Bytes, VecExt};
use crate::control_transfers::descriptors::{get_version_2_hub_device_descriptor, GetStandardUsbDescriptorError};
use crate::control_transfers::descriptors::get_version_3_hub_device_descriptor;
use crate::serde::TryReserveErrorRemote;
use super::DeadOrAlive;
use super::DeviceConnection;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::MaybeUninit;
use std::mem::transmute;
use crate::descriptors::DescriptorHeaderLength;
use crate::descriptors::descriptor_index;
use super::DeadOrAlive::Alive;
use swiss_army_knife::get_unchecked::GetUnchecked;
use std::num::NonZeroU8;
use super::physical_location::PortNumber;
use std::collections::TryReserveError;
use std::hash::Hash;
use crate::class_and_protocol::DeviceClass;
use crate::version::Version;
use swiss_army_knife::non_zero::new_non_zero_u8;


include!("DownstreamPortSetting.rs");
include!("DownstreamPorts.rs");
include!("HubDescriptor.rs");
include!("HubDescriptorParseError.rs");
include!("HubDescriptorTrait.rs");
include!("LogicalPowerSwitchingMode.rs");
include!("OvercurrentProtectionMode.rs");
include!("PacketHeaderDecodeLatency.rs");
include!("TransactionTranslatorThinkTime.rs");
include!("Version2DownstreamPortSetting.rs");
include!("Version2HubDescriptor.rs");
include!("Version2HubDescriptorParseError.rs");
include!("Version3DownstreamPortSetting.rs");
include!("Version3HubDescriptor.rs");
include!("Version3HubDescriptorParseError.rs");
