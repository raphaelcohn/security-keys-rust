// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::VecExt;
use super::additional_descriptors::AdditionalDescriptor;
use super::additional_descriptors::AdditionalDescriptorParseError;
use super::additional_descriptors::AdditionalDescriptorParser;
use super::additional_descriptors::DescriptorType;
use super::additional_descriptors::parse_additional_descriptors;
use super::errors::UsbError;
use super::interface::UsbInterface;
use super::interface::smart_card::SmartCardInterfaceAdditionalDescriptor;
use super::UsbStringFinder;
use super::UsbStringOrIndex;
use rusb::ConfigDescriptor;
use rusb::DeviceDescriptor;
use rusb::UsbContext;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::collections::TryReserveError;
use std::convert::Infallible;
use std::num::NonZeroU8;
use swiss_army_knife::non_zero::new_non_zero_u8;


include!("ConfigurationAdditionalDescriptor.rs");
include!("ConfigurationAdditionalDescriptorParser.rs");
include!("ConfigurationNumber.rs");
include!("UsbConfiguration.rs");
