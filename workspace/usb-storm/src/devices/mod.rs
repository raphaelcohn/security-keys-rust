// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::collections::VecExt;
use crate::context::Context;
use crate::device::DeadOrFailedToParseDeviceDetails;
use crate::device::Device;
use crate::device::DeviceReference;
use crate::device::DeviceReferenceParseError;
use crate::device::ListDevicesError;
use crate::device::ReusableBuffer;
use crate::serde::TryReserveErrorRemote;
use either::Left;
use either::Right;
use libusb1_sys::libusb_device;
use libusb1_sys::libusb_free_device_list;
use libusb1_sys::libusb_get_device_list;
use libusb1_sys::constants::LIBUSB_ERROR_IO;
use libusb1_sys::constants::LIBUSB_ERROR_INVALID_PARAM;
use libusb1_sys::constants::LIBUSB_ERROR_ACCESS;
use libusb1_sys::constants::LIBUSB_ERROR_NO_DEVICE;
use libusb1_sys::constants::LIBUSB_ERROR_BUSY;
use libusb1_sys::constants::LIBUSB_ERROR_TIMEOUT;
use libusb1_sys::constants::LIBUSB_ERROR_NOT_FOUND;
use libusb1_sys::constants::LIBUSB_ERROR_OVERFLOW;
use libusb1_sys::constants::LIBUSB_ERROR_PIPE;
use libusb1_sys::constants::LIBUSB_ERROR_INTERRUPTED;
use libusb1_sys::constants::LIBUSB_ERROR_NO_MEM;
use libusb1_sys::constants::LIBUSB_ERROR_NOT_SUPPORTED;
use libusb1_sys::constants::LIBUSB_ERROR_OTHER;
use likely::likely;
use serde::Deserialize;
use serde::Serialize;
use std::collections::TryReserveError;
use std::error;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::mem::MaybeUninit;
use std::mem::transmute;
use std::ops::Deref;
use std::ptr::NonNull;
use std::slice::from_raw_parts;
use swiss_army_knife::non_zero::new_non_null;


include!("Devices.rs");
include!("DevicesParseError.rs");
include!("GoodAndBadDevices.rs");
