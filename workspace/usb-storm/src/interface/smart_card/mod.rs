// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::additional_descriptors::AdditionalDescriptorParser;
use crate::additional_descriptors::DescriptorType;
use crate::additional_descriptors::verify_remaining_bytes;
use crate::class_and_protocol::SmartCardProtocol;
use crate::version::Version;
use self::features::Features;
use self::features::FeaturesParseError;
use self::features::LevelOfExchange;
use crate::Bytes;
use enumflags2::bitflags;
use enumflags2::BitFlags;
use likely::likely;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::num::NonZeroU8;
use swiss_army_knife::non_zero::new_non_zero_u8;
use crate::version::VersionParseError;


/// Features of a smart card.
pub mod features;


include!("Baud.rs");
include!("BytesExt.rs");
include!("Iso7816Protocol.rs");
include!("Kilohertz.rs");
include!("LcdLayout.rs");
include!("MechanicalFeature.rs");
include!("PinSupport.rs");
include!("SmartCardInterfaceAdditionalDescriptor.rs");
include!("SmartCardInterfaceAdditionalDescriptorParseError.rs");
include!("SmartCardInterfaceAdditionalDescriptorParser.rs");
include!("SynchronizationProtocol.rs");
include!("T0ProtocolUnconfiguredClass.rs");
include!("T0ProtocolUnconfiguredClasses.rs");
include!("VoltageSupport.rs");
