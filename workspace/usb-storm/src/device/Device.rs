// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// USB device.
#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Device
{
	bus_number: u8,

	address: u8,

	port_number: PortNumber,

	port_numbers: ArrayVec<PortNumber, MaximumDevicePortNumbers>,
	
	speed: Option<Speed>,
	
	control_end_point_zero_maximum_packet_size_exponent: u8,
	
	vendor_identifier: VendorIdentifier,
	
	product_identifier: ProductIdentifier,
	
	maximum_supported_usb_version: Version,
	
	manufacturer_device_version: Version,
	
	class_and_protocol: ClassAndProtocol<Self>,
	
	languages: Option<Vec<Language>>,
	
	manufacturer: Option<LocalizedStrings>,
	
	product_name: Option<LocalizedStrings>,
	
	serial_number: Option<LocalizedStrings>,
	
	configurations: IndexMap<ConfigurationNumber, Configuration>,
	
	active_configuration_number: Option<ConfigurationNumber>,
}

impl DeviceOrAlternateSetting for Device
{
}

impl Device
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
	pub const fn port_number(&self) -> PortNumber
	{
		self.port_number
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn port_numbers(&self) -> ArrayVec<PortNumber, MaximumDevicePortNumbers>
	{
		self.port_numbers
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn speed(&self) -> Option<Speed>
	{
		self.speed
	}
	
	/// An exponent; the maximum packet size is `2 << maximum_packet_size_exponent`.
	#[inline(always)]
	pub const fn control_end_point_zero_maximum_packet_size_exponent(&self) -> u8
	{
		self.control_end_point_zero_maximum_packet_size_exponent
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn vendor_identifier(&self) -> VendorIdentifier
	{
		self.vendor_identifier
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn product_identifier(&self) -> ProductIdentifier
	{
		self.vendor_identifier
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_supported_usb_version(&self) -> Version
	{
		self.maximum_supported_usb_version
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn manufacturer_device_version(&self) -> Version
	{
		self.manufacturer_device_version
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn class_and_protocol(&self) -> ClassAndProtocol<Self>
	{
		self.class_and_protocol
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn languages(&self) -> Option<&[Language]>
	{
		match self.languages
		{
			None => None,
			
			Some(ref languages) => Some(languages.get_unchecked_range_safe(..))
		}
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn manufacturer(&self) -> Option<&LocalizedStrings>
	{
		self.manufacturer.as_ref()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn product_name(&self) -> Option<&LocalizedStrings>
	{
		self.product_name.as_ref()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn serial_number(&self) -> Option<&LocalizedStrings>
	{
		self.serial_number.as_ref()
	}
	
	/// Can be empty, unlike other collections for interfaces and alternate settings.
	///
	/// `.iter().enumerate()` does not produce indices suitable for use with `libusb_get_config_descriptor()`.
	/// The key is suitable for use with `libusb_get_config_descriptor_by_value()` and `libusb_set_configuration()`.
	#[inline(always)]
	pub fn configurations(&self) -> &IndexMap<ConfigurationNumber, Configuration>
	{
		&self.configurations
	}
	
	/// `None` if not actively configured.
	#[inline(always)]
	pub fn active_configuration_number(&self) -> Option<ConfigurationNumber>
	{
		self.active_configuration_number
	}
	
	// #[inline(always)]
	// pub(crate) fn active_smart_card_interface_additional_descriptors(&self) -> Result<Vec<&SmartCardInterfaceAdditionalDescriptor>, UsbDeviceError>
	// {
	// 	if self.class_and_protocol.is_valid_smart_card_device()
	// 	{
	// 		match self.cached_active_configuration()?
	// 		{
	// 			None => return Ok(Vec::new()),
	//
	// 			Some(active_configuration) => active_configuration.smart_card_interface_additional_descriptors().map_err(UsbDeviceError::Allocation),
	// 		}
	// 	}
	// 	else
	// 	{
	// 		Ok(Vec::new())
	// 	}
	// }
	//
	// #[inline(always)]
	// pub(crate) fn cached_active_configuration(&self) -> Result<Option<&Configuration>, UsbDeviceError>
	// {
	// 	if let Some(active_configuration) = self.active_configuration
	// 	{
	// 		match self.configurations.get(&active_configuration)
	// 		{
	// 			Some(configuration) => Ok(Some(configuration)),
	//
	// 			None => Err(UsbDeviceError::ActiveConfigurationNotInConfiguations)
	// 		}
	// 	}
	// 	else
	// 	{
	// 		Ok(None)
	// 	}
	// }
	
	#[inline(always)]
	pub(super) fn parse(libusb_device: NonNull<libusb_device>) -> Result<DeadOrAlive<Self>, DeviceParseError>
	{
		use DeadOrAlive::*;
		use DeviceParseError::*;
		
		let device_handle = match DeviceHandle::open(libusb_device)?
		{
			Dead => return Ok(Dead),
			
			Alive(device_handle) => device_handle,
		};
		
		let string_finder = match StringFinder::new(&device_handle).map_err(GetLanguages)?
		{
			Dead => return Ok(Dead),
			
			Alive(string_finder) => string_finder
		};
		
		let device_descriptor = get_device_descriptor(libusb_device);
		let maximum_supported_usb_version = Version::parse(device_descriptor.bcdUSB).map_err(MaximumSupportedUsbVersion)?;
		let speed = get_device_speed(libusb_device);
		let configurations = match Self::get_configurations(libusb_device, &device_descriptor, maximum_supported_usb_version, speed, &string_finder)?
		{
			Dead => return Ok(Dead),
			
			Alive(configurations) => configurations,
		};
		Ok
		(
			Alive
			(
				Device
				{
					bus_number: get_bus_number(libusb_device),
				
					address: get_device_address(libusb_device),
					
					port_number: get_port_number(libusb_device),
				
					port_numbers: get_port_numbers(libusb_device),
				
					speed,
					
					control_end_point_zero_maximum_packet_size_exponent: device_descriptor.bMaxPacketSize0,
					
					vendor_identifier: device_descriptor.idVendor,
					
					product_identifier: device_descriptor.idProduct,
				
					maximum_supported_usb_version,
					
					manufacturer_device_version: Version::parse(device_descriptor.bcdDevice).map_err(FirmwareVersion)?,
					
					class_and_protocol: ClassAndProtocol::new_from_device(&device_descriptor),
					
					manufacturer: match string_finder.find_string(device_descriptor.iManufacturer).map_err(ManufacturerString)?
					{
						Dead => return Ok(Dead),
						
						Alive(string) => string,
					},
					
					product_name: match string_finder.find_string(device_descriptor.iProduct).map_err(ProductNameString)?
					{
						Dead => return Ok(Dead),
						
						Alive(string) => string,
					},
					
					serial_number: match string_finder.find_string(device_descriptor.iSerialNumber).map_err(SerialNumberString)?
					{
						Dead => return Ok(Dead),
						
						Alive(string) => string,
					},
					
					active_configuration_number: match Self::get_active_configuration_number(libusb_device, &configurations)?
					{
						Dead => return Ok(Dead),
						
						Alive(active_configuration_number) => active_configuration_number,
					},
					
					configurations,
					
					languages: string_finder.into_languages().map_err(CouldNotAllocateMemoryForLanguages)?,
				}
			)
		)
	}
	
	#[inline(always)]
	fn get_configurations(libusb_device: NonNull<libusb_device>, device_descriptor: &libusb_device_descriptor, maximum_supported_usb_version: Version, speed: Option<Speed>, string_finder: &StringFinder) -> Result<DeadOrAlive<IndexMap<ConfigurationNumber, Configuration>>, DeviceParseError>
	{
		use DeadOrAlive::*;
		use DeviceParseError::*;
		
		let bNumConfigurations = device_descriptor.bNumConfigurations;
		if unlikely!(bNumConfigurations > MaximumNumberOfConfigurations)
		{
			return Err(TooManyConfigurations { bNumConfigurations })
		}
		
		let mut configurations = IndexMap::with_capacity(bNumConfigurations as usize);
		for configuration_index in 0 .. bNumConfigurations
		{
			match get_config_descriptor(libusb_device, configuration_index).map_err(|cause| GetConfigurationDescriptor { cause, configuration_index })?
			{
				Dead => return Ok(Dead),
				
				Alive(Some(configuration_descriptor)) =>
				{
					let (configuration_number, configuration) = match Configuration::parse(configuration_descriptor, maximum_supported_usb_version, speed, string_finder).map_err(|cause| ParseConfigurationDescriptor { cause, configuration_index })?
					{
						Dead => return Ok(Dead),
						
						Alive(alive) => alive,
					};
					
					let outcome = configurations.insert(configuration_number, configuration);
					if unlikely!(outcome.is_some())
					{
						return Err(DuplicateConfigurationNumber { configuration_index, configuration_number })
					}
				},
			}
		}
		
		Ok(Alive(configurations))
	}
	
	#[inline(always)]
	fn get_active_configuration_number(libusb_device: NonNull<libusb_device>, configurations: &IndexMap<ConfigurationNumber, Configuration>) -> Result<DeadOrAlive<Option<ConfigurationNumber>>, DeviceParseError>
	{
		use DeadOrAlive::*;
		use DeviceParseError::*;
		
		if unlikely!(configurations.is_empty())
		{
			return Ok(Alive(None))
		}
		
		let configuration_number = match get_active_config_descriptor(libusb_device).map_err(GetActiveConfigurationDescriptor)?
		{
			Dead => return Ok(Dead),
			
			Alive(None) => return Ok(Alive(None)),
			
			Alive(Some(configuration_descriptor)) => Configuration::parse_configuration_number_only(&configuration_descriptor).map_err(ParseConfigurationNumberOfActiveConfigurationDescriptor)?,
		};
		
		Ok(Alive(Some(configuration_number)))
	}
	
	// /// Obtain current USB devices on all buses.
	// #[inline(always)]
	// pub fn usb_devices_try_from() -> Result<Vec<Self>, UsbError>
	// {
	// 	let device_list = devices().map_err(UsbError::ListDevices)?;
	// 	let mut devices = Vec::with_capacity(device_list.len());
	// 	for device in device_list.iter()
	// 	{
	// 		devices.push(Self::try_from(device)?);
	// 	}
	// 	Ok(devices)
	// }
}
