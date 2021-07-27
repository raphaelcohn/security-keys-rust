// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


fn EXP(driver_location: DriverLocation) -> Result<(), LoadError>
{
	let drivers = driver_location.load_drivers()?;
	let devices = UsbDevice::usb_devices_try_from().map_err(LoadError::FindingUsbDevices)?;
	
	for device in devices
	{
		let active_smart_card_interface_additional_descriptors = device.active_smart_card_interface_additional_descriptors()?;
		if !active_smart_card_interface_additional_descriptors.is_empty()
		{
			let vendor_identifier = device.vendor_identifier;
			let product_identifier = device.product_identifier;
			
			// If this is Mac OS, we have to use the friendly name (?why)?
			
			//drivers.get_supported_device(vendor_identifier, product_identifier);
			
			
			for ccid_device_descriptor in active_smart_card_interface_additional_descriptors
			{
			
			}
		}
	}
	
	Ok(())
}

/*
	ccid_usb
	
	loop over all indices ('alias') of ifdVendorID
	
	interface_number = -1
	if !apple
	{
		device_bus = 0
		device_addr = 0
		if device.is_not_null()
		{
			device_vendor = substring(device, blah)
			device_product = substring(device, blah)
			
			interface_number = substring(device, blah)
			device_bus = substring(device, blah)
			device_addr = substring(device, blah)
		}
	}
	
	let usb_devices = devices();
	
	for alias in 0 .. vendors.len()
	{
		if apple
		{
			if device.is_not_null()
			{
				if device != vendors[alias].friendlyName
				{
					continue
				}
			}
		}
		else
		{
			if device.is_not_null()
			{
				if device_vendor != vendors[alias].vendorId && device_product != vendors[alias].productId
				{
					continue
				}
			}
		}
		
		for usb_device in usb_devices
		{
			bus_number = usb_device.bus_number();
			device_address = usb_device.device_address();
			
			if !apple
			{
				// device-addres 0 is special.
				if device_bus != 0 || device_addr != 0
				{
					if bus_number != device_bus
					{
						continue
					}
					if device_address != device_addr
					{
						continue
					}
				}
			}
			
			let desc = usb_device.device_descriptor();
			
			if (desc.idVendor == vendors[alias].vendorId && desc.idProduct == vendors[alias].productId)
			{
				let readerID = (vendors[alias].vendorId << 16) + vendors[alias].productId;
				
				if use_composite_as_multi_slot
				{
					max_interface_number = 2;
					if readerID is known composite
					{
						max_interface_number = someting-device-specific (1 or 3)
					}
				}
				
				let already_used = has_device_been_opened_previously(bus_number, device_address);
				if already_used
				{
					if is_multi_slot
					{
						multislot_extension = Multi_CreateNextSlot(previous_reader_index);
					}
					else
					{
						if interface_number == -1
						{
							continue
						}
					}
				}
			}
		}
		
	}

 */
