// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use crate::MaximumDevicePortNumbers;
use crate::UsbPortNumber;
use crate::UsbSpeed;
use arrayvec::ArrayVec;
use libusb1_sys::LIBUSB_ERROR_OVERFLOW;
use libusb1_sys::LIBUSB_SPEED_FULL;
use libusb1_sys::LIBUSB_SPEED_HIGH;
use libusb1_sys::LIBUSB_SPEED_LOW;
use libusb1_sys::LIBUSB_SPEED_SUPER;
use libusb1_sys::LIBUSB_SPEED_UNKNOWN;
use libusb1_sys::libusb_device;
use libusb1_sys::libusb_device_descriptor;
use libusb1_sys::libusb_get_bus_number;
use libusb1_sys::libusb_get_device_address;
use libusb1_sys::libusb_get_device_descriptor;
use libusb1_sys::libusb_get_device_speed;
use libusb1_sys::libusb_get_parent;
use libusb1_sys::libusb_get_port_number;
use libusb1_sys::libusb_get_port_numbers;
use std::mem::MaybeUninit;
use std::mem::transmute;
use std::ptr::NonNull;


include!("device_descriptor.rs");
include!("get_bus_number.rs");
include!("get_device_address.rs");
include!("get_device_speed.rs");
include!("get_parent.rs");
include!("get_port_number.rs");
include!("get_port_numbers.rs");
