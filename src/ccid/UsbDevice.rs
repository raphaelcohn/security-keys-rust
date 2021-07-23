// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct UsbDevice
{
	bus_number: u8,

	address: u8,

	port_number: u8,

	port_numbers: Vec<u8>,

	speed: Speed,

	vendor_identifier: u16,

	product_identifier: u16,
	
	maximum_supported_usb_version: Version,
	
	manufacturer_device_version: Version,
	
	class_code: u8,

	sub_class_code: u8,

	protocol_code: u8,
	
	languages: Option<Vec<Language>>,
	
	manufacturer_string: Option<UsbStringOrIndex>,
	
	product_string: Option<UsbStringOrIndex>,
	
	serial_number_string: Option<UsbStringOrIndex>,
	
	configurations: Vec<UsbConfiguration>,
}

impl TryFrom for UsbDevice
{
	type Error = UsbError;
	
	#[inline(always)]
	fn try_from(device: Device<impl UsbContext>) -> Result<Self, Self::Error>
	{
		use self::UsbError::*;
		
		let bus_number = device.bus_number();
		let address = device.address();
		let port_number = device.port_number();
		
		let device_descriptor = device.device_descriptor().map_err(GetDeviceDescriptor)?;
		//let active_configuration_descriptor = device.active_config_descriptor().map_err(GetDeviceActiveConfigDescriptor)?;
		let _first_end_point_maximum_packet_size = device_descriptor.max_packet_size();
		let usb_string_finder = UsbStringFinder::new(&device)?;
		
		Ok
		(
			UsbDevice
			{
				bus_number,
			
				address,
				
				port_number,
			
				port_numbers:
				{
					let port_numbers = device.port_numbers().map_err(GetDevicePortNumbers)?;
					debug_assert!(port_numbers.len() <= 7);
					port_numbers
				},
			
				speed: device.speed(),
				
				vendor_identifier: device_descriptor.vendor_id(),
				
				product_identifier: device_descriptor.product_id(),
			
				maximum_supported_usb_version: device_descriptor.usb_version(),
				
				manufacturer_device_version: device_descriptor.device_version(),
			
				class_code: device_descriptor.class_code(),
			
				sub_class_code: device_descriptor.sub_class_code(),
			
				protocol_code: device_descriptor.protocol_code(),
				
				manufacturer_string: usb_string_finder.find(device_descriptor.manufacturer_string_index())?,
				
				product_string: usb_string_finder.find(device_descriptor.product_string_index())?,
				
				serial_number_string: usb_string_finder.find(device_descriptor.serial_number_string_index())?,
				
				configurations: UsbConfiguration::usb_configurations_try_from(device_descriptor, &usb_string_finder)?,
				
				languages: usb_string_finder.into_languages(),
			}
		)
	}
}

impl UsbDevice
{
	#[inline(always)]
	pub(crate) fn usb_devices_try_from() -> Result<Vec<Self>, UsbError>
	{
		let device_list = devices().map_err(UsbError::ListDevices)?;
		let mut devices = Vec::with_capacity(device_list.len());
		for device in device_list.iter()
		{
			devices.push(Self::try_from(device)?);
		}
		Ok(devices)
	}
}
