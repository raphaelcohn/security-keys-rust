// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// USB device.
#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UsbDevice
{
	bus_number: u8,

	address: u8,

	port_number: u8,

	port_numbers: Vec<u8>,

	speed: UsbSpeed,
	
	pub(crate) vendor_identifier: UsbVendorIdentifier,
	
	pub(crate) product_identifier: UsbProductIdentifier,
	
	maximum_supported_usb_version: UsbVersion,
	
	manufacturer_device_version: UsbVersion,
	
	class_and_protocol: UsbClassAndProtocol<Device>,
	
	languages: Option<Vec<UsbLanguage>>,
	
	manufacturer_string: Option<UsbStringOrIndex>,
	
	product_string: Option<UsbStringOrIndex>,
	
	serial_number_string: Option<UsbStringOrIndex>,
	
	active_configuration: Option<NonZeroU8>,
	
	configurations: HashMap<NonZeroU8, UsbConfiguration>,
}

impl<T: UsbContext> TryFrom<rusb::Device<T>> for UsbDevice
{
	type Error = UsbError;
	
	#[inline(always)]
	fn try_from(device: rusb::Device<T>) -> Result<Self, Self::Error>
	{
		use self::UsbError::*;
		
		let bus_number = device.bus_number();
		let address = device.address();
		let port_number = device.port_number();
		
		let device_descriptor = device.device_descriptor().map_err(GetDeviceDescriptor)?;
		let _first_end_point_maximum_packet_size = device_descriptor.max_packet_size();
		let usb_string_finder = UsbStringFinder::new(&device);
		
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
			
				speed: device.speed().into(),
				
				vendor_identifier: device_descriptor.vendor_id(),
				
				product_identifier: device_descriptor.product_id(),
			
				maximum_supported_usb_version: device_descriptor.usb_version().into(),
				
				manufacturer_device_version: device_descriptor.device_version().into(),
				
				class_and_protocol: UsbClassAndProtocol::new
				(
					device_descriptor.class_code(),
					
					device_descriptor.sub_class_code(),
					
					device_descriptor.protocol_code(),
				),
				
				manufacturer_string: usb_string_finder.find(device_descriptor.manufacturer_string_index())?,
				
				product_string: usb_string_finder.find(device_descriptor.product_string_index())?,
				
				serial_number_string: usb_string_finder.find(device_descriptor.serial_number_string_index())?,
				
				active_configuration: match device.active_config_descriptor()
				{
					Ok(config_descriptor) => Some(new_non_zero_u8(config_descriptor.number())),
					
					Err(rusb::Error::NotFound) => None,
					
					Err(cause) => return Err(GetDeviceActiveConfigDescriptor(cause)),
				},
				
				configurations: UsbConfiguration::usb_configurations_try_from(&device, device_descriptor, &usb_string_finder)?,
				
				languages: usb_string_finder.into_languages(),
			}
		)
	}
}

impl UsbDevice
{
	#[inline(always)]
	pub(crate) fn is_currently_configured_as_circuit_card_interface_device(&self) -> Result<Vec<CcidDeviceDescriptor>, UsbDeviceError>
	{
		if self.class_and_protocol.is_device_probable_circuit_card_interface_device()
		{
			match self.cached_active_configuration()?
			{
				None => return Ok(Vec::new()),
				
				Some(active_configuration) => active_configuration.is_circuit_card_interface_device().map_err(UsbDeviceError::InvalidCcidDeviceDescriptor),
			}
		}
		else
		{
			Ok(Vec::new())
		}
	}
	
	#[inline(always)]
	pub(crate) fn cached_active_configuration(&self) -> Result<Option<&UsbConfiguration>, UsbDeviceError>
	{
		if let Some(active_configuration) = self.active_configuration
		{
			match self.configurations.get(&active_configuration)
			{
				Some(configuration) => Ok(Some(configuration)),
				
				None => Err(UsbDeviceError::ActiveConfigurationNotInConfiguations)
			}
		}
		else
		{
			Ok(None)
		}
	}
	
	/// Obtain current USB devices on all buses.
	#[inline(always)]
	pub fn usb_devices_try_from() -> Result<Vec<Self>, UsbError>
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
