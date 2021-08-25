// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::end_point::directional_transfer_type::Direction;
use libusb1_sys::libusb_clear_halt;
use libusb1_sys::libusb_control_transfer;
use libusb1_sys::libusb_device_handle;
use libusb1_sys::constants::LIBUSB_ERROR_ACCESS;
use libusb1_sys::constants::LIBUSB_ERROR_BUSY;
use libusb1_sys::constants::LIBUSB_ERROR_INTERRUPTED;
use libusb1_sys::constants::LIBUSB_ERROR_INVALID_PARAM;
use libusb1_sys::constants::LIBUSB_ERROR_IO;
use libusb1_sys::constants::LIBUSB_ERROR_NOT_FOUND;
use libusb1_sys::constants::LIBUSB_ERROR_NOT_SUPPORTED;
use libusb1_sys::constants::LIBUSB_ERROR_NO_DEVICE;
use libusb1_sys::constants::LIBUSB_ERROR_NO_MEM;
use libusb1_sys::constants::LIBUSB_ERROR_OTHER;
use libusb1_sys::constants::LIBUSB_ERROR_OVERFLOW;
use libusb1_sys::constants::LIBUSB_ERROR_PIPE;
use libusb1_sys::constants::LIBUSB_ERROR_TIMEOUT;
use libusb1_sys::constants::LIBUSB_RECIPIENT_DEVICE;
use libusb1_sys::constants::LIBUSB_RECIPIENT_ENDPOINT;
use libusb1_sys::constants::LIBUSB_RECIPIENT_INTERFACE;
use libusb1_sys::constants::LIBUSB_RECIPIENT_OTHER;
use libusb1_sys::constants::LIBUSB_REQUEST_CLEAR_FEATURE;
use libusb1_sys::constants::LIBUSB_REQUEST_GET_CONFIGURATION;
use libusb1_sys::constants::LIBUSB_REQUEST_GET_DESCRIPTOR;
use libusb1_sys::constants::LIBUSB_REQUEST_GET_INTERFACE;
use libusb1_sys::constants::LIBUSB_REQUEST_GET_STATUS;
use libusb1_sys::constants::LIBUSB_REQUEST_SET_ADDRESS;
use libusb1_sys::constants::LIBUSB_REQUEST_SET_CONFIGURATION;
use libusb1_sys::constants::LIBUSB_REQUEST_SET_DESCRIPTOR;
use libusb1_sys::constants::LIBUSB_REQUEST_SET_FEATURE;
use libusb1_sys::constants::LIBUSB_REQUEST_SET_INTERFACE;
use libusb1_sys::constants::LIBUSB_REQUEST_SET_SEL;
use libusb1_sys::constants::LIBUSB_REQUEST_SYNCH_FRAME;
use libusb1_sys::constants::LIBUSB_REQUEST_TYPE_CLASS;
use libusb1_sys::constants::LIBUSB_REQUEST_TYPE_STANDARD;
use libusb1_sys::constants::LIBUSB_REQUEST_TYPE_VENDOR;
use libusb1_sys::constants::LIBUSB_SET_ISOCH_DELAY;
use likely::likely;
use likely::unlikely;
use std::cmp::min;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::ptr::NonNull;
use std::time::Duration;
use std::mem::MaybeUninit;
use swiss_army_knife::get_unchecked::GetUnchecked;


/// Descriptors.
pub mod descriptors;


include!("control_transfer.rs");
include!("control_transfer_in.rs");
include!("ControlTransferError.rs");
include!("ControlTransferRecipient.rs");
include!("ControlTransferRequestType.rs");
include!("Request.rs");
include!("TimeOut.rs");
