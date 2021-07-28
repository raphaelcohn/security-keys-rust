// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::additional_descriptors::AdditionalDescriptor;
use super::additional_descriptors::AdditionalDescriptorParseError;
use super::additional_descriptors::AdditionalDescriptorParser;
use super::additional_descriptors::parse_additional_descriptors;
use super::additional_descriptors::DescriptorType;
use super::errors::UsbError;
use indexmap::IndexMap;
use rusb::Direction;
use rusb::EndpointDescriptor;
use rusb::InterfaceDescriptor;
use rusb::TransferType;
use rusb::SyncType;
use rusb::UsageType;
use serde::Deserialize;
use serde::Serialize;
use std::convert::Infallible;
use std::mem::transmute;


include!("EndPointNumber.rs");
include!("EndPointAdditionalDescriptor.rs");
include!("EndPointAdditionalDescriptorParser.rs");
include!("IsochronousAndInterrruptAdditionalTransactionOpportunitiesPerMicroframe.rs");
include!("u4.rs");
include!("u11.rs");
include!("UsbDirection.rs");
include!("UsbEndPoint.rs");
include!("UsbTransferType.rs");
include!("UsbIschronousTransferSynchronizationType.rs");
include!("UsbIschronousTransferUsageType.rs");
