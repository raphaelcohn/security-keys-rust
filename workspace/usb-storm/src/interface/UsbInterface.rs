// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An USB interface.
#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UsbInterface
{
	/// Should linearly increase from zero for each configuration.
	interface_number: u8,

	interface_alternate_settings: Vec<UsbInterfaceAlternateSetting>
}

impl UsbInterface
{
	/// Does not check the alternate settings of the interface.
	#[inline(always)]
	pub(super) fn smart_card_interface_additional_descriptor(&self) -> Option<&SmartCardInterfaceAdditionalDescriptor>
	{
		self.interface_alternate_settings.get_unchecked_safe(0).smart_card_interface_additional_descriptor()
	}
	
	#[inline(always)]
	fn try_from(interface: rusb::Interface, usb_string_finder: &UsbStringFinder<impl UsbContext>) -> Result<Self, UsbError>
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
	pub(super) fn usb_interfaces_try_from(configuration_descriptor: ConfigDescriptor, usb_string_finder: &UsbStringFinder<impl UsbContext>) -> Result<Vec<Self>, UsbError>
	{
		use self::UsbError::*;
		
		let number_of_interfaces = configuration_descriptor.num_interfaces();
		if unlikely!(number_of_interfaces == 0)
		{
			return Err(NoInterfaces)
		}
		let mut interfaces = Vec::with_capacity(number_of_interfaces as usize);
		for interface in configuration_descriptor.interfaces()
		{
			interfaces.try_push(Self::try_from(interface, usb_string_finder)?).map_err(CouldNotPushInterface)?;
		}
		debug_assert!(interfaces.len() > 0, "No interfaces for configuration");
		Ok(interfaces)
	}
}
