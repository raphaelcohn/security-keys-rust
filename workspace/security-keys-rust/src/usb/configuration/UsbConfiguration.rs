// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UsbConfiguration
{
	maximum_power_in_milliamps: u16,
	
	is_self_powered: bool,
	
	supports_remote_wake_up: bool,
	
	configuration_string: Option<UsbStringOrIndex>,
	
	interfaces: Vec<UsbInterface>,

	extra: Vec<AdditionalDescriptor<ConfigurationAdditionalDescriptor>>,
}

impl UsbConfiguration
{
	#[inline(always)]
	pub(super) fn smart_card_interface_additional_descriptors(&self) -> Result<Vec<&SmartCardInterfaceAdditionalDescriptor>, TryReserveError>
	{
		// A small number of cards have more than one interface.
		let mut smart_card_interface_additional_descriptors = Vec::new_with_capacity(self.interfaces.len())?;
		for interface in self.interfaces.iter()
		{
			if let Some(smart_card_interface_additional_descriptor) = interface.smart_card_interface_additional_descriptor()
			{
				smart_card_interface_additional_descriptors.push(smart_card_interface_additional_descriptor);
			}
		}
		
		smart_card_interface_additional_descriptors.shrink_to_fit();
		Ok(smart_card_interface_additional_descriptors)
	}
	
	#[inline(always)]
	fn try_from(configuration_descriptor: ConfigDescriptor, usb_string_finder: &UsbStringFinder<impl UsbContext>) -> Result<Self, UsbError>
	{
		Ok
		(
			Self
			{
				maximum_power_in_milliamps: configuration_descriptor.max_power(),
				
				is_self_powered: configuration_descriptor.self_powered(),
				
				supports_remote_wake_up: configuration_descriptor.remote_wakeup(),
				
				configuration_string: usb_string_finder.find(configuration_descriptor.description_string_index())?,
				
				extra: Self::parse_additional_descriptors(&configuration_descriptor).map_err(UsbError::CouldNotParseConfigurationAdditionalDescriptor)?,
				
				interfaces: UsbInterface::usb_interfaces_try_from(configuration_descriptor, usb_string_finder)?,
			}
		)
	}
	
	#[inline(always)]
	pub(super) fn usb_configurations_try_from<T: UsbContext>(device: &rusb::Device<T>, device_descriptor: DeviceDescriptor, usb_string_finder: &UsbStringFinder<T>) -> Result<HashMap<ConfigurationNumber, Self>, UsbError>
	{
		use self::UsbError::*;
		
		let number_of_configurations = device_descriptor.num_configurations();
		let mut configurations = HashMap::with_capacity(number_of_configurations as usize);
		for configuration_descriptor_index in 0 .. number_of_configurations
		{
			let configuration_descriptor = device.config_descriptor(configuration_descriptor_index).map_err(|cause| GetDeviceConfigurationDescriptor { cause, configuration_descriptor_index })?;
			let configuration_number = new_non_zero_u8(configuration_descriptor.number());
			let _ = configurations.insert(configuration_number, Self::try_from(configuration_descriptor, usb_string_finder)?);
		}
		Ok(configurations)
	}
	
	#[inline(always)]
	fn parse_additional_descriptors(configuration_descriptor: &ConfigDescriptor) -> Result<Vec<AdditionalDescriptor<ConfigurationAdditionalDescriptor>>, AdditionalDescriptorParseError<Infallible>>
	{
		let mut additional_descriptor_parser = ConfigurationAdditionalDescriptorParser;
		parse_additional_descriptors(configuration_descriptor.extra(), additional_descriptor_parser)
	}
}
