// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


struct Context
{
	driver: Arc<Driver>,
	
	logical_unit_number: LogicalUnitNumber,
}

impl Context
{
	/// Closely mirrors `IFDOpenIFD()` in `ifdwrapper.c`.
	///
	/// It is possible to pass `None` for `usb_device_name`, but it is unclear what actually then happens inside `OpenUSBByName()` in `ccid_usb.c`.
	fn create_channel(&self, usb_device_name: Option<&UsbDeviceName>)
	{
		let response_code = match usb_device_name
		{
			None => self.driver.create_channel_using_ignored_channel_identifier(self.logical_unit_number),
			
			Some(usb_device_name) =>
			{
				let usb_device_name = usb_device_name.as_c_str();
				let length = usb_device_name.to_bytes_with_nul().len();
				debug_assert!(length <= MAX_DEVICENAME);
				self.driver.create_channel_using_name(self.logical_unit_number, usb_device_name.borrow())
			}
		};

		unimplemented!("panic")
		
		// match response_code
		// {
		// 	IFD_SUCCESS => (),
		//
		// 	// eg for ifd-ccid, no more reader indices; defined by CCID_DRIVER_MAX_READERS, which is 16 or could not open USB device.
		// 	IFD_COMMUNICATION_ERROR => (),
		//
		// 	// There is no card reader for the device name.
		// 	IFD_NO_SUCH_DEVICE => (),
		//
		// 	_ => (),
		// }
	}
}
