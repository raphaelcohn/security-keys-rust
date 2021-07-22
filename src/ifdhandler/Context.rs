// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


struct Context
{
	driver: Arc<Driver>,

	logical_unit_number_or_slot: LogicalUnitNumber,
}

impl Context
{
	fn new(driver: &Arc<Driver>, slot_index: u16) -> Self
	{
		Self
		{
			driver: driver.clone(),
		
			logical_unit_number_or_slot: LogicalUnitNumber::from_slot_index(slot_index),
		}
	}
	
	/*
		TODO: Unset or control environment variables (CCID)
			LANG
			TERM
			LIBCCID_ifdLogLevel
			
	
		TODO: Unset or control environment variables (shared)
			PCSCLITE_DEBUG
			MUSCLECARD_DEBUG
			TERM
		
		TODO: unset environment variables (PC/SC)
			PCSCLITE_FILTER_IGNORE_READER_NAMES
			PCSCLITE_FILTER_EXTEND_READER_NAMES
			PCSCLITE_NO_BLOCKING
			PCSCLITE_CSOCK_NAME
			
		fullname, libudev
			format!("{}", friendly_name)
			format!("{} [{}]", friendly_name, interface_name)
			format!("{} [{}] ({})", friendly_name, interface_name, serial_number)
			format!("{} ({})", friendly_name, serial_number)
			NB: interface_name has non-ascii characters replaced with '.'
			NB: serial_number is not appended if it is already present in interface_name
			NB: interface_name and serial_number can be null.
			fullname is also called readerNameLong and later readerName.
		
		readerName is then adjusted as format!("{}{} {:02X} 00", readerName, extend, i) where  slot = i << 16  and extend is the value of the env variable PCSCLITE_FILTER_EXTEND_READER_NAMES
		
		port is a u32 of two parts;
		
		port & 0xFFFF_0000 may contain PCSCLITE_HP_BASE_PORT if the reader is hotplugged
		
		IFDGetCapabilities is called on existing readers when installing a new reader, to ensure that the maximum number of channels is not exceeded and to share mutexes.
	 */
	
	/// Closely mirrors `IFDOpenIFD()` in `ifdwrapper.c`.
	///
	/// It is possible to pass `None` for `usb_device_name`, but it is unclear what actually then happens inside `OpenUSBByName()` in `ccid_usb.c`.
	fn create_channel(&self, usb_device_name: Option<&UsbDeviceName>)
	{
		let response_code = match usb_device_name
		{
			None => self.driver.create_channel_using_ignored_channel_identifier(logical_unit_number_or_slot),
			
			Some(usb_device_name) =>
			{
				let usb_device_name = usb_device_name.as_c_str().borrow();
				let length = usb_device_name.to_bytes_with_nul().len();
				debug_assert!(length <= MAX_DEVICENAME);
				self.driver.functions.IFDHCreateChannelByName(logical_unit_number_or_slot, usb_device_name)
			}
		};
		
		match response_code
		{
			IFD_SUCCESS => (),
			
			// eg for ifd-ccid, no more reader indices; defined by CCID_DRIVER_MAX_READERS, which is 16 or could not open USB device.
			IFD_COMMUNICATION_ERROR => (),
			
			// There is no card reader for the device name.
			IFD_NO_SUCH_DEVICE => (),
			
			_ => (),
		}
	}
}
