// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use indexmap::IndexMap;
use rusb::Direction;
use rusb::EndpointDescriptor;
use rusb::InterfaceDescriptor;
use rusb::TransferType;
use rusb::SyncType;
use rusb::UsageType;
use serde::Deserialize;
use serde::Serialize;
use std::num::NonZeroU8;
use swiss_army_knife::non_zero::new_non_zero_u8;
use std::mem::transmute;


include!("IsochronousAndInterrruptAdditionalTransactionOpportunitiesPerMicroframe.rs");
include!("new_non_zero_u4.rs");
include!("NonZeroU4.rs");
include!("u11.rs");
include!("UsbDirection.rs");
include!("UsbEndPoint.rs");
include!("UsbTransferType.rs");
include!("UsbIschronousTransferSynchronizationType.rs");
include!("UsbIschronousTransferUsageType.rs");
