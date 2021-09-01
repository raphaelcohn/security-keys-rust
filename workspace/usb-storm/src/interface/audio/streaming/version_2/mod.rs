// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use crate::interface::audio::control::entity_identifiers::TerminalEntityIdentifier;
use crate::descriptors::verify_remaining_bytes;
use crate::descriptors::DescriptorType;
use crate::descriptors::DescriptorSubType;
use crate::descriptors::descriptor_index;
use crate::collections::Bytes;
use crate::collections::WrappedBitFlags;
use crate::interface::audio::Control;
use crate::interface::audio::control::version_2_entities::logical_audio_channel_cluster::Version2LogicalAudioChannelCluster;
use crate::interface::audio::control::version_2_entities::logical_audio_channel_cluster::Version2LogicalAudioChannelClusterParseError;
use crate::string::StringFinder;
use crate::interface::audio::control::logical_audio_channels::LogicalAudioChannelClusterParseError;
use crate::device::DeadOrAlive::Alive;
use crate::device::DeadOrAlive;
use swiss_army_knife::get_unchecked::GetUnchecked;


include!("AudioSubSlotSizeInBytes.rs");
include!("Decoder.rs");
include!("DecoderParseError.rs");
include!("Encoder.rs");
include!("EncoderParseError.rs");
include!("FormatTypeDescriptorParseError.rs");
include!("General.rs");
include!("GeneralControlsParseError.rs");
include!("GeneralParseError.rs");
include!("SideBandProtocol.rs");
include!("Version2AudioFormatDetails.rs");
include!("Version2AudioFormatExtendedTypeIDetails.rs");
include!("Version2AudioFormatExtendedTypeIIDetails.rs");
include!("Version2AudioFormatExtendedTypeIIIDetails.rs");
include!("Version2AudioFormatTypeI.rs");
include!("Version2AudioFormatTypeIDetails.rs");
include!("Version2AudioFormatTypeII.rs");
include!("Version2AudioFormatTypeIIDetails.rs");
include!("Version2AudioFormatTypeIII.rs");
include!("Version2AudioFormatTypeIIIDetails.rs");
include!("Version2AudioFormatTypeIV.rs");
include!("Version2AudioStreamingInterfaceExtraDescriptor.rs");
include!("Version2AudioStreamingInterfaceExtraDescriptorParseError.rs");
