// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::integers::u4;
use super::integers::u11;
use self::transfer_type::TransferType;
use self::transfer_type::TransferTypeParseError;
use super::additional_descriptors::AdditionalDescriptor;
use super::additional_descriptors::AdditionalDescriptorParseError;
use super::additional_descriptors::AdditionalDescriptorParser;
use super::additional_descriptors::extra_to_slice;
use super::additional_descriptors::parse_additional_descriptors;
use super::additional_descriptors::DescriptorType;
use libusb1_sys::libusb_endpoint_descriptor;
use libusb1_sys::constants::LIBUSB_DT_ENDPOINT;
use likely::unlikely;
use serde::Deserialize;
use serde::Serialize;
use std::convert::Infallible;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use crate::version::Version;


/// Transfer.
pub mod transfer_type;


include!("EndPoint.rs");
include!("EndPointNumber.rs");
include!("EndPointAdditionalDescriptor.rs");
include!("EndPointAdditionalDescriptorParser.rs");
include!("EndPointAudioExtension.rs");
include!("EndPointParseError.rs");
include!("InclusiveMaximumNumberOfEndPoints.rs");
