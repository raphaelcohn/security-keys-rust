// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use libusb1_sys::libusb_endpoint_descriptor;
use libusb1_sys::constants::LIBUSB_ENDPOINT_DIR_MASK;
use libusb1_sys::constants::LIBUSB_ENDPOINT_IN;
use libusb1_sys::constants::LIBUSB_ENDPOINT_OUT;
use libusb1_sys::constants::LIBUSB_ISO_SYNC_TYPE_ADAPTIVE;
use libusb1_sys::constants::LIBUSB_ISO_SYNC_TYPE_ASYNC;
use libusb1_sys::constants::LIBUSB_ISO_SYNC_TYPE_MASK;
use libusb1_sys::constants::LIBUSB_ISO_SYNC_TYPE_NONE;
use libusb1_sys::constants::LIBUSB_ISO_SYNC_TYPE_SYNC;
use libusb1_sys::constants::LIBUSB_ISO_USAGE_TYPE_DATA;
use libusb1_sys::constants::LIBUSB_ISO_USAGE_TYPE_FEEDBACK;
use libusb1_sys::constants::LIBUSB_ISO_USAGE_TYPE_IMPLICIT;
use libusb1_sys::constants::LIBUSB_ISO_USAGE_TYPE_MASK;
use libusb1_sys::constants::LIBUSB_TRANSFER_TYPE_BULK;
use libusb1_sys::constants::LIBUSB_TRANSFER_TYPE_CONTROL;
use libusb1_sys::constants::LIBUSB_TRANSFER_TYPE_INTERRUPT;
use libusb1_sys::constants::LIBUSB_TRANSFER_TYPE_ISOCHRONOUS;
use libusb1_sys::constants::LIBUSB_TRANSFER_TYPE_MASK;
use serde::Deserialize;
use serde::Serialize;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::mem::transmute;
use crate::version::Version;
use std::num::NonZeroU8;
use swiss_army_knife::non_zero::new_non_zero_u8;


include!("AdditionalTransactionOpportunitiesPerMicroframe.rs");
include!("Direction.rs");
include!("InterruptUsageType.rs");
include!("IschronousTransferSynchronizationType.rs");
include!("IschronousTransferUsageType.rs");
include!("TransferType.rs");
include!("TransferTypeParseError.rs");
