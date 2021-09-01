// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use likely::unlikely;
use self::version_1::Version1AudioStreamingInterfaceExtraDescriptor;
use self::version_1::Version1AudioStreamingInterfaceExtraDescriptorParseError;
use self::version_2::Version2AudioStreamingInterfaceExtraDescriptor;
use self::version_2::Version2AudioStreamingInterfaceExtraDescriptorParseError;
use self::version_3::Version3AudioStreamingInterfaceExtraDescriptor;
use self::version_3::Version3AudioStreamingInterfaceExtraDescriptorParseError;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use crate::class_and_protocol::AudioProtocol;
use crate::descriptors::DescriptorSubType;
use crate::descriptors::DescriptorParser;
use crate::descriptors::DescriptorHeaderLength;
use crate::descriptors::DescriptorType;
use crate::descriptors::verify_remaining_bytes;
use crate::string::StringFinder;
use crate::device::DeadOrAlive;
use crate::interface::audio::control::AudioControlInterfaceExtraDescriptorParser;
use crate::collections::VecExt;
use crate::collections::Bytes;
use std::collections::TryReserveError;
use crate::control_transfers::descriptors::MinimumStandardUsbDescriptorLength;
use crate::device::DeadOrAlive::Alive;


/// Version 1.
pub mod version_1;


/// Version 2.
pub mod version_2;


/// Version 3.
pub mod version_3;


include!("AudioStreamingInterfaceExtraDescriptor.rs");
include!("AudioStreamingInterfaceExtraDescriptorParseError.rs");
include!("AudioStreamingInterfaceExtraDescriptorParser.rs");
