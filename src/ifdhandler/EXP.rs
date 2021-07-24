// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


fn EXP(driver_location: DriverLocation) -> Result<(), LoadError>
{
	let drivers = driver_location.load_drivers()?;
	let devices = UsbDevice::usb_devices_try_from().map_err(LoadError::FindingUsbDevices)?;
	
	for device in devices
	{
		let ccid_device_descriptors = device.is_currently_configured_as_circuit_card_interface_device()?;
		if !ccid_device_descriptors.is_empty()
		{
			let vendor_identifier = device.vendor_identifier;
			let product_identifier = device.product_identifier;
			
			// If this is Mac OS, we have to use the friendly name (?why)?
			
			drivers.get_supported_device(vendor_identifier, product_identifier);
			
			
			for ccid_device_descriptor in ccid_device_descriptors
			{
			
			}
		}
	}
	
	Ok(())
}
