// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::Bytes;
use crate::collections::VecExt;
use crate::interface::audio::CS_INTERFACE;
use crate::descriptors::DescriptorHeaderLength;
use crate::descriptors::DescriptorSubType;
use crate::descriptors::DescriptorType;
use crate::descriptors::descriptor_index;
use crate::descriptors::descriptor_index_non_constant;
use crate::descriptors::verify_remaining_bytes;
use crate::integers::u24;
use crate::interface::audio::control::entity_identifiers::TerminalEntityIdentifier;
use crate::interface::audio::streaming::Ac3Common;
use crate::interface::audio::streaming::GenericAudioStreamingInterfaceExtraDescriptorParseError;
use crate::serde::TryReserveErrorRemote;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::mem::transmute;
use super::MpegCommon;
use swiss_army_knife::get_unchecked::GetUnchecked;


include!("Hertz.rs");
include!("FormatTypeIIIParseError.rs");
include!("FormatTypeIIParseError.rs");
include!("FormatTypeIParseError.rs");
include!("FormatTypeParseError.rs");
include!("SamplingFrequency.rs");
include!("SamplingFrequencyParseError.rs");
include!("SubframeSize.rs");
include!("Version1AudioFormat.rs");
include!("Version1AudioFormatDetail.rs");
include!("Version1AudioStreamingInterfaceExtraDescriptor.rs");
include!("Version1AudioStreamingInterfaceExtraDescriptorParseError.rs");
include!("Version1TypeIAudioFormat.rs");
include!("Version1TypeIAudioFormatDetail.rs");
include!("Version1TypeIIAudioFormatDetailSpecific.rs");
include!("Version1TypeIIAudioFormat.rs");
include!("Version1TypeIIAudioFormatDetail.rs");
include!("Version1TypeIIIAudioFormat.rs");
include!("Version1TypeIIIAudioFormatDetail.rs");
