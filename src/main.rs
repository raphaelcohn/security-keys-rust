// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use security_keys_rust::usb::UsbDevice;
use security_keys_rust::usb::UsbError;


fn main() -> Result<(), UsbError>
{
	let usb_devices = UsbDevice::usb_devices_try_from()?;
	
	
	
	Ok(())
}
