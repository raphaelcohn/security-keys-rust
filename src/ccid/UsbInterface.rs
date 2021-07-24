// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct UsbInterface
{
	/// Should linearly increase from zero for each configuration.
	interface_number: u8,

	interface_alternate_settings: Vec<UsbInterfaceAlternateSetting>
}

impl UsbInterface
{
	/// Does not check the alternate settings of the interface.
	#[inline(always)]
	fn is_circuit_card_interface_device(&self) -> Result<Option<CcidDeviceDescriptor>, &'static str>
	{
		self.interface_alternate_settings.get_unchecked_safe(0).is_circuit_card_interface_device()
	}
	
	#[inline(always)]
	fn try_from(interface: Interface, usb_string_finder: &UsbStringFinder<impl UsbContext>) -> Result<Self, UsbError>
	{
		Ok
		(
			Self
			{
				interface_number: interface.number(),
				
				interface_alternate_settings: UsbInterfaceAlternateSetting::usb_interface_alternate_settings_try_from(interface, usb_string_finder)?,
			}
		)
	}
	
	#[inline(always)]
	fn usb_interfaces_try_from(configuration_descriptor: ConfigDescriptor, usb_string_finder: &UsbStringFinder<impl UsbContext>) -> Result<Vec<Self>, UsbError>
	{
		let number_of_interfaces = configuration_descriptor.num_interfaces();
		let mut interfaces = Vec::with_capacity(number_of_interfaces as usize);
		for interface in configuration_descriptor.interfaces()
		{
			interfaces.push(Self::try_from(interface, usb_string_finder)?);
		}
		debug_assert!(interfaces.len() > 0, "No interfaces for configuration");
		Ok(interfaces)
	}
}
