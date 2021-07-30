// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(super) fn serialize<'a, W: Write, F: FnOnce(W) -> S, S>(writer: W, constructor: F) -> Result<(), ()>
where &'a mut S: 'static + Serializer<Ok=()>
{
	usb_devices_serialize(writer, |writer, usb_devices|
	{
		let mut serializer = constructor(writer);
		let reference = &mut serializer;
		let borrow_checker_hack = unsafe { &mut * (reference as *mut S) };
		usb_devices.serialize(borrow_checker_hack)
	})
}
