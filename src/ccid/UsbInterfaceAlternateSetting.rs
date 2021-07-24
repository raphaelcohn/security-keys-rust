// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct UsbInterfaceAlternateSetting
{
	alternate_setting_number: u8,
	
	class_code: u8,
	
	sub_class_code: u8,
	
	protocol_code: u8,

	description: Option<UsbStringOrIndex>,

	end_points: Vec<UsbEndPoint>,
}

impl UsbInterfaceAlternateSetting
{
	#[inline(always)]
	fn try_from(interface_descriptor: InterfaceDescriptor, usb_string_finder: &UsbStringFinder<impl UsbContext>) -> Result<Self, UsbError>
	{
		Ok
		(
			Self
			{
				alternate_setting_number: interface_descriptor.setting_number(),
				
				class_code: interface_descriptor.class_code(),
				
				sub_class_code: interface_descriptor.sub_class_code(),
				
				protocol_code: interface_descriptor.protocol_code(),
				
				description: usb_string_finder.find(interface_descriptor.description_string_index())?,
			
				end_points: UsbEndPoint::usb_end_points_from(interface_descriptor),
			}
		)
	}
	
	#[inline(always)]
	fn usb_interface_alternate_settings_try_from(interface: Interface, usb_string_finder: &UsbStringFinder<impl UsbContext>) -> Result<Vec<Self>, UsbError>
	{
		let interface_alternate_settings_iterator = interface.descriptors();
		let mut interface_alternate_settings =
		{
			let capacity = match interface_alternate_settings_iterator.size_hint()
			{
				(lower, None) => lower,
				
				(lower, Some(upper)) => upper,
			};
			Vec::with_capacity(capacity)
		};
		
		for interface_alternate_setting in interface_alternate_settings_iterator
		{
			interface_alternate_settings.push(Self::try_from(interface_alternate_setting, usb_string_finder)?);
		}
		Ok(interface_alternate_settings)
	}
}
