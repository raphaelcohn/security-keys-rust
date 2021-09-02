// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::integers::u4;
use super::integers::u11;
use self::directional_transfer_type::BulkMaximumStreamsExponent;
use self::directional_transfer_type::Direction;
use self::directional_transfer_type::SuperSpeedBulk;
use self::directional_transfer_type::SuperSpeedInterrupt;
use self::directional_transfer_type::SuperSpeedIsochronous;
use self::directional_transfer_type::DirectionalTransferType;
use self::directional_transfer_type::TransferTypeParseError;
use super::descriptors::DescriptorParseError;
use super::descriptors::DescriptorParser;
use super::descriptors::DescriptorType;
use super::descriptors::extra_to_slice;
use super::descriptors::parse_descriptors;
use super::descriptors::verify_remaining_bytes;
use either::Either;
use either::Left;
use either::Right;
use indexmap::map::Entry;
use libusb1_sys::libusb_endpoint_descriptor;
use libusb1_sys::constants::LIBUSB_DT_ENDPOINT;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use crate::version::Version;
use crate::collections::Bytes;
use crate::collections::WrappedIndexMap;
use crate::descriptors::descriptor_index;
use swiss_army_knife::non_zero::new_non_zero_u8;
use swiss_army_knife::non_zero::new_non_zero_u32;
use crate::integers::u2;
use crate::integers::NonZeroU4;
use swiss_army_knife::get_unchecked::GetUnchecked;
use crate::descriptors::reduce_b_length_to_descriptor_body_length;
use crate::descriptors::DescriptorHeaderLength;
use crate::string::StringFinder;
use crate::device::DeadOrAlive;
use crate::device::Speed;
use crate::device::DeadOrAlive::Alive;
use std::num::NonZeroU8;
use crate::class_and_protocol::AudioSubClass;
use crate::class_and_protocol::MassStorageProtocol;
use crate::class_and_protocol::MassStorageSubClass;
use crate::class_and_protocol::InterfaceClass;
use crate::end_point::audio::AudioStreamingIsochronousEndPoint;
use crate::end_point::audio::AudioStreamingIsochronousEndPointParseError;


/// Audio.
pub mod audio;


/// Directional transfers.
pub mod directional_transfer_type;


include!("DirectionalEndPoint.rs");
include!("EndPoint.rs");
include!("EndPointAudioExtension.rs");
include!("EndPointCommon.rs");
include!("EndPointCommonAndDirectionalTransferType.rs");
include!("EndPointExtraDescriptor.rs");
include!("EndPointExtraDescriptorParseError.rs");
include!("EndPointExtraDescriptorParser.rs");
include!("EndPointNumber.rs");
include!("EndPointParseError.rs");
include!("InclusiveMaximumNumberOfEndPoints.rs");
include!("SuperSpeedEndPointCompanionDescriptorParser.rs");
include!("SuperSpeedEndPointCompanionDescriptorParseError.rs");
include!("SuperSpeedPlusIsochronousEndPointCompanionDescriptorParseError.rs");
include!("UsbAttachedScsiPipeIdentifier.rs");
include!("UsbAttachedScsiPipeParseError.rs");
