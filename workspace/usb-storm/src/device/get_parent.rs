// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// NOTE: Only valid if a device list is currently held!
#[inline(always)]
pub(super) fn get_parent(libusb_device: NonNull<libusb_device>) -> Option<NonNull<libusb_device>>
{
	unsafe { transmute(libusb_get_parent(libusb_device.as_ptr())) }
}
