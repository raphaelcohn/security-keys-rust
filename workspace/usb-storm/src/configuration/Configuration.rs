// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// USB configuration.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration
{
	maximum_power_consumption: MaximumPowerConsumption,
	
	supports_remote_wake_up: bool,
	
	description: Option<LocalizedStrings>,
	
	additional_descriptors: Vec<AdditionalDescriptor<ConfigurationAdditionalDescriptor>>,
	
	interfaces: WrappedIndexMap<InterfaceNumber, Interface>,
}

impl Configuration
{
	/// `None` if the device is not bus-powered.
	#[inline(always)]
	pub const fn maximum_power_consumption(&self) -> MaximumPowerConsumption
	{
		self.maximum_power_consumption
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn supports_remote_wake_up(&self) -> bool
	{
		self.supports_remote_wake_up
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn description(&self) -> Option<&LocalizedStrings>
	{
		self.description.as_ref()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn interfaces(&self) -> &WrappedIndexMap<InterfaceNumber, Interface>
	{
		&self.interfaces
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn additional_descriptors(&self) -> &[AdditionalDescriptor<ConfigurationAdditionalDescriptor>]
	{
		&self.additional_descriptors
	}
	
	// #[inline(always)]
	// pub(super) fn smart_card_interface_additional_descriptors(&self) -> Result<Vec<&SmartCardInterfaceAdditionalDescriptor>, TryReserveError>
	// {
	// 	// A small number of cards have more than one interface.
	// 	let mut smart_card_interface_additional_descriptors = Vec::new_with_capacity(self.interfaces.len())?;
	// 	for interface in self.interfaces.iter()
	// 	{
	// 		if let Some(smart_card_interface_additional_descriptor) = interface.smart_card_interface_additional_descriptor()
	// 		{
	// 			smart_card_interface_additional_descriptors.push(smart_card_interface_additional_descriptor);
	// 		}
	// 	}
	//
	// 	smart_card_interface_additional_descriptors.shrink_to_fit();
	// 	Ok(smart_card_interface_additional_descriptors)
	// }
	
	#[inline(always)]
	pub(super) fn parse_configuration_number_only(configuration_descriptor: &ConfigurationDescriptor) -> Result<ConfigurationNumber, ConfigurationParseError>
	{
		Self::validate_configuration_descriptor(&configuration_descriptor)?;
		Self::parse_configuration_number(&configuration_descriptor)
	}
	
	#[inline(always)]
	pub(super) fn parse(configuration_descriptor: ConfigurationDescriptor, maximum_supported_usb_version: Version, speed: Option<Speed>, string_finder: &StringFinder) -> Result<DeadOrAlive<(ConfigurationNumber, Self)>, ConfigurationParseError>
	{
		use ConfigurationParseError::*;
		
		let configuration_number = Self::parse_configuration_number_only(&configuration_descriptor)?;
		
		let (supports_remote_wake_up, is_self_powered_or_self_powered_and_bus_powered) = Self::parse_attributes(&configuration_descriptor)?;
		let description = string_finder.find_string(configuration_descriptor.iConfiguration).map_err(DescriptionString)?;
		let additional_descriptors = Self::parse_additional_descriptors(string_finder, &configuration_descriptor).map_err(CouldNotParseConfigurationAdditionalDescriptor)?;
		let interfaces = Self::parse_interfaces(&configuration_descriptor, string_finder, maximum_supported_usb_version)?;
		Ok
		(
			Alive
			(
				(
					configuration_number,
					
					Self
					{
						maximum_power_consumption: MaximumPowerConsumption::parse(&configuration_descriptor, speed, is_self_powered_or_self_powered_and_bus_powered)?,
						
						supports_remote_wake_up,
						
						description: return_ok_if_dead!(description),
						
						additional_descriptors: return_ok_if_dead!(additional_descriptors),
						
						interfaces: return_ok_if_dead!(interfaces),
					}
				)
			)
		)
	}
	
	#[inline(always)]
	fn validate_configuration_descriptor(configuration_descriptor: &libusb_config_descriptor) -> Result<(), ConfigurationParseError>
	{
		use ConfigurationParseError::*;
		
		const LIBUSB_DT_CONFIG_SIZE: u8 = 9;
		let bLength = configuration_descriptor.bLength;
		if unlikely!(bLength < LIBUSB_DT_CONFIG_SIZE)
		{
			return Err(WrongLength { bLength })
		}
		
		let bDescriptorType = configuration_descriptor.bDescriptorType;
		if unlikely!(bDescriptorType != LIBUSB_DT_CONFIG)
		{
			return Err(WrongDescriptorType { bDescriptorType })
		}
		
		let wTotalLength = configuration_descriptor.wTotalLength;
		if unlikely!(wTotalLength < (LIBUSB_DT_CONFIG_SIZE as u16))
		{
			return Err(WrongTotalLength { wTotalLength })
		}
	
		Ok(())
	}
	
	#[inline(always)]
	fn parse_number_of_interfaces(configuration_descriptor: &libusb_config_descriptor) -> Result<NonZeroU8, ConfigurationParseError>
	{
		use ConfigurationParseError::*;
		
		let bNumInterfaces = configuration_descriptor.bNumInterfaces;
		
		if unlikely!(bNumInterfaces == 0)
		{
			return Err(NoInterfaces)
		}
		
		if unlikely!(bNumInterfaces > MaximumNumberOfInterfaces)
		{
			return Err(TooManyInterfaces { bNumInterfaces })
		}
		
		Ok(new_non_zero_u8(bNumInterfaces))
	}
	
	#[inline(always)]
	fn parse_configuration_number(configuration_descriptor: &libusb_config_descriptor) -> Result<ConfigurationNumber, ConfigurationParseError>
	{
		let bConfigurationValue = configuration_descriptor.bConfigurationValue;
		if unlikely!(bConfigurationValue == 0)
		{
			Err(ConfigurationParseError::ConfigurationValueWasZero)
		}
		else
		{
			Ok(new_non_zero_u8(bConfigurationValue))
		}
	}
	
	#[inline(always)]
	fn parse_attributes(configuration_descriptor: &libusb_config_descriptor) -> Result<(bool, bool), ConfigurationParseError>
	{
		use ConfigurationParseError::*;
		
		let bmAttributes = configuration_descriptor.bmAttributes;
		
		if unlikely!(bmAttributes & 0b1000_0000 == 0)
		{
			return Err(AttributesBitSevenIsNotOne)
		}
		
		if unlikely!(bmAttributes & 0b0001_1111 != 0)
		{
			return Err(AttributesBitsZeroToFourAreNotZero)
		}
		
		let supports_remote_wake_up = bmAttributes & 0x20 != 0;
		let is_self_powered_or_bus_and_self_powered = bmAttributes & 0x40 != 0;
		
		Ok((supports_remote_wake_up, is_self_powered_or_bus_and_self_powered))
	}
	
	#[inline(always)]
	fn parse_additional_descriptors(string_finder: &StringFinder, configuration_descriptor: &libusb_config_descriptor) -> Result<DeadOrAlive<Vec<AdditionalDescriptor<ConfigurationAdditionalDescriptor>>>, AdditionalDescriptorParseError<Infallible>>
	{
		let extra = extra_to_slice(configuration_descriptor.extra, configuration_descriptor.extra_length)?;
		
		let additional_descriptor_parser = ConfigurationAdditionalDescriptorParser;
		parse_additional_descriptors(string_finder, extra, additional_descriptor_parser)
	}
	
	#[inline(always)]
	fn parse_interfaces(configuration_descriptor: &libusb_config_descriptor, string_finder: &StringFinder, maximum_supported_usb_version: Version) -> Result<DeadOrAlive<WrappedIndexMap<InterfaceNumber, Interface>>, ConfigurationParseError>
	{
		use ConfigurationParseError::*;
		
		let number_of_interfaces = Self::parse_number_of_interfaces(configuration_descriptor)?;
		let libusb_interfaces = Self::libusb_interfaces_as_slice(configuration_descriptor, number_of_interfaces)?;
		
		let mut interfaces = WrappedIndexMap::with_capacity(number_of_interfaces).map_err(CouldNotAllocateMemoryForInterfaces)?;
		for interface_index in 0 .. number_of_interfaces.get()
		{
			let libusb_interface = libusb_interfaces.get_unchecked_safe(interface_index);
			let (interface_number, interface) = return_ok_if_dead!(Interface::parse(libusb_interface, string_finder, interface_index, maximum_supported_usb_version).map_err(|cause| CouldNotParseInterface { cause, interface_index })?);
			
			let outcome = interfaces.insert(interface_number, interface);
			if unlikely!(outcome.is_some())
			{
				return Err(DuplicateInterface { interface_index, interface_number })
			}
		}
		
		Ok(Alive(interfaces))
	}
	
	#[inline(always)]
	fn libusb_interfaces_as_slice(configuration_descriptor: &libusb_config_descriptor, number_of_interfaces: NonZeroU8) -> Result<&[libusb_interface], ConfigurationParseError>
	{
		let interface_pointer = configuration_descriptor.interface;
		if unlikely!(interface_pointer.is_null())
		{
			return Err(ConfigurationParseError::NullInterfacePointer)
		}
		
		Ok(unsafe { from_raw_parts(interface_pointer, number_of_interfaces.get() as usize) })
	}
}
