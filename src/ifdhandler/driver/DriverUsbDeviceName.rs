// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[cfg(any(target_os = "ios", target_os = "macos"))]
pub(super) struct DriverUsbDeviceName
{
	friendly_name: CString,
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(super) struct DriverUsbDeviceName
{
	/// Also known as manufacturer identifier.
	vendor_identifier: UsbVendorIdentifier,

	product_identifier: UsbProductIdentifier,
	
	/// `udev_device_get_sysattr_value(dev, "bInterfaceNumber")`.
	///
	/// If not known defaults to `0`; usually `0` for most card readers.
	interface_number: u8,
	
	/// Typically limited to a number between `0` and `255`.
	bus_number: u8,
	
	/// Typically limited to a number between `0` and `255`.
	///
	/// USB 3.0 has theoretical support for 7,906 end points.
	device_number: u16,
}

impl DriverUsbDeviceName
{
	#[cfg(any(target_os = "ios", target_os = "macos"))]
	pub(super) fn as_c_str(&self) -> Cow<CStr>
	{
		Cow::Borrowed(&self.friendly_name)
	}
	
	#[cfg(any(target_os = "android", target_os = "linux"))]
	#[inline(always)]
	pub(super) fn as_c_str(&self) -> Cow<CStr>
	{
		let string = format!("usb:{:04x}/{:04x}:libudev:{}:/dev/bus/usb/{:03}/{:03}", self.vendor_identifier, self.product_identifier, self.bInterfaceNumber, self.bus_number, self.device_number);
		Cow::Owned(CString::new(string).unwrap())
	}
}
