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

	port_number: UsbPortNumber,

	port_numbers: ArrayVec<UsbPortNumber, MaximumDevicePortNumbers>,
	
	speed: Option<UsbSpeed>,
	
	/// An exponent; the maximum packet size is `2 << maximum_packet_size_exponent`.
	control_end_point_zero_maximum_packet_size_exponent: u8,
	
	vendor_identifier: UsbVendorIdentifier,
	
	product_identifier: UsbProductIdentifier,
	
	maximum_supported_usb_version: UsbVersion,
	
	manufacturer_device_version: UsbVersion,
	
	class_and_protocol: UsbClassAndProtocol<Device>,
	
	languages: Option<Vec<UsbLanguage>>,
	
	manufacturer_string: Option<UsbStringOrIndex>,
	
	product_string: Option<UsbStringOrIndex>,
	
	serial_number_string: Option<UsbStringOrIndex>,
	
	active_configuration: Option<ConfigurationNumber>,
	
	configurations: HashMap<ConfigurationNumber, UsbConfiguration>,
}

impl<T: UsbContext> TryFrom<rusb::Device<T>> for UsbDevice
{
	type Error = UsbError;
	
	#[inline(always)]
	fn try_from(device: rusb::Device<T>) -> Result<Self, Self::Error>
	{
		use self::UsbError::*;
		
		let libusb_device = new_non_null(device.as_raw());
		let device_descriptor = device_descriptor(libusb_device);
		let usb_string_finder = UsbStringFinder::new(&device);
		
		Ok
		(
			UsbDevice
			{
				bus_number: get_bus_number(libusb_device),
			
				address: get_device_address(libusb_device),
				
				port_number: get_port_number(libusb_device),
			
				port_numbers: get_port_numbers(libusb_device),
			
				speed: get_device_speed(libusb_device),
				
				control_end_point_zero_maximum_packet_size_exponent: device_descriptor.bMaxPacketSize0,
				
				vendor_identifier: device_descriptor.idVendor,
				
				product_identifier: device_descriptor.idProduct,
			
				maximum_supported_usb_version: UsbVersion::try_from(device_descriptor.bcdUSB).map_err(DeviceUsbVersion)?,
				
				manufacturer_device_version: UsbVersion::try_from(device_descriptor.bcdDevice).map_err(DeviceFirmwareVersion)?,
				
				class_and_protocol: UsbClassAndProtocol::new_from_device(&device_descriptor),
				
				manufacturer_string: usb_string_finder.find_string(device_descriptor.iManufacturer)?,
				
				product_string: usb_string_finder.find_string(device_descriptor.iProduct)?,
				
				serial_number_string: usb_string_finder.find_string(device_descriptor.iSerialNumber)?,
				
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
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn bus_number(&self) -> u8
	{
		self.bus_number
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn address(&self) -> u8
	{
		self.address
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn port_number(&self) -> u8
	{
		self.port_number
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn port_numbers(&self) -> ArrayVec<u8, 7>
	{
		self.port_numbers
	}
	
	#[inline(always)]
	pub(crate) fn active_smart_card_interface_additional_descriptors(&self) -> Result<Vec<&SmartCardInterfaceAdditionalDescriptor>, UsbDeviceError>
	{
		if self.class_and_protocol.is_valid_smart_card_device()
		{
			match self.cached_active_configuration()?
			{
				None => return Ok(Vec::new()),
				
				Some(active_configuration) => active_configuration.smart_card_interface_additional_descriptors().map_err(UsbDeviceError::Allocation),
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
