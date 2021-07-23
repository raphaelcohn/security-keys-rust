// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct UsbConfiguration
{
	bConfigurationValue: u8,
	
	maximum_power_in_milliamps: u16,
	
	is_self_powered: bool,
	
	supports_remote_wake_up: bool,
	
	configuration_string: Option<UsbStringOrIndex>,
	
	interfaces: Vec<UsbInterface>,
}

impl UsbConfiguration
{
	#[inline(always)]
	fn try_from(configuration_descriptor: ConfigDescriptor, usb_string_finder: &UsbStringFinder<impl UsbContext>) -> Result<Self, UsbError>
	{
		use self::UsbError::*;
		Ok
		(
			Self
			{
				bConfigurationValue: configuration_descriptor.number(),
				
				maximum_power_in_milliamps: configuration_descriptor.max_power(),
				
				is_self_powered: configuration_descriptor.self_powered(),
				
				supports_remote_wake_up: configuration_descriptor.remote_wakeup(),
				
				configuration_string: usb_string_finder.find(configuration_descriptor.description_string_index())?,
				
				interfaces: UsbInterface::usb_interfaces_try_from(configuration_descriptor, usb_string_finder)?,
			}
		)
	}
	
	#[inline(always)]
	fn usb_configurations_try_from(device_descriptor: DeviceDescriptor, usb_string_finder: &UsbStringFinder<impl UsbContext>) -> Result<Vec<Self>, UsbError>
	{
		use self::UsbError::*;
		
		let number_of_configurations = device_descriptor.num_configurations();
		let mut configurations = Vec::with_capacity(number_of_configurations as usize);
		for configuration_descriptor_index in 0 .. number_of_configurations
		{
			let configuration_descriptor = device.config_descriptor(configuration_descriptor_index).map_err(|cause| GetDeviceConfigurationDescriptor { cause, configuration_descriptor_index })?;
			configurations.push(Self::try_from(configuration_descriptor, usb_string_finder)?);
		}
		Ok(configurations)
	}
}
