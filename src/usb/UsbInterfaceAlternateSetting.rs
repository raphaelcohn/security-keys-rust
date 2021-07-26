// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Represents an Interface Descriptor.
#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UsbInterfaceAlternateSetting
{
	/// Should linearly increase from zero for each interface.
	alternate_setting_number: u8,
	
	class_and_protocol: UsbClassAndProtocol,

	description: Option<UsbStringOrIndex>,

	end_points: IndexMap<u4, UsbEndPoint>,
	
	extra: Vec<u8>,
}

impl UsbInterfaceAlternateSetting
{
	#[inline(always)]
	fn is_circuit_card_interface_device(&self) -> Result<Option<CcidDeviceDescriptor>, &'static str>
	{
		match self.class_and_protocol.is_interface_circuit_card_interface_device(self.extra.len() == CcidDeviceDescriptor::Length)
		{
			Some(protocol) => match self.extract_ccid_device_descriptor(protocol)
			{
				Ok(ccid_device_descriptor) => Ok(Some(ccid_device_descriptor)),
				
				Err(message) => Err(message),
			},
			
			None => Ok(None),
		}
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn extract_ccid_device_descriptor(&self, protocol: CcidProtocol) -> Result<CcidDeviceDescriptor, &'static str>
	{
		match self.extra.len()
		{
			CcidDeviceDescriptor::Length => self.new_ccid_device_descriptor(protocol, &self.extra),
			
			// Devices such as the O2 Micro Oz776, Reiner SCT and bluedrive II incorrectly put the device descriptor at the end of the end points (what is it with USB device manufacturers not being able to read specs)?
			// That said, these devices are now very rare.
			0 => match self.end_points.last()
			{
				None => Err("Non-standard CCID does not have extra data in final end point"),
				
				Some((_, last_end_point)) =>
				{
					let extra = &last_end_point.extra;
					if extra.len() == CcidDeviceDescriptor::Length
					{
						self.new_ccid_device_descriptor(protocol, &self.extra)
					}
					else
					{
						Err("Non-standard CCID has extra data in final end point which is not of length 54")
					}
				}
			},
			
			_ => Err("Non-standard CCID has extra data which is neither 54 or 0 bytes long")
		}
	}
	
	#[inline(always)]
	fn new_ccid_device_descriptor<'a>(&'a self, protocol: CcidProtocol, extra: &'a [u8]) -> Result<CcidDeviceDescriptor<'a>, &'static str>
	{
		CcidDeviceDescriptor::new(self, protocol, extra)
	}
	
	#[inline(always)]
	fn try_from(interface_descriptor: InterfaceDescriptor, usb_string_finder: &UsbStringFinder<impl UsbContext>) -> Result<Self, UsbError>
	{
		Ok
		(
			Self
			{
				alternate_setting_number: interface_descriptor.setting_number(),
				
				class_and_protocol: UsbClassAndProtocol
				{
					class_code: interface_descriptor.class_code(),
					
					sub_class_code: interface_descriptor.sub_class_code(),
					
					protocol_code: interface_descriptor.protocol_code(),
				},
				
				description: usb_string_finder.find(interface_descriptor.description_string_index())?,
			
				extra: match interface_descriptor.extra()
				{
					None => Vec::new(),
					
					Some(bytes) =>
					{
						debug_assert_ne!(bytes.len(), 0);
						bytes.to_vec()
					}
				},
				
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
				
				(_, Some(upper)) => upper,
			};
			Vec::with_capacity(capacity)
		};
		
		for interface_alternate_setting in interface_alternate_settings_iterator
		{
			interface_alternate_settings.push(Self::try_from(interface_alternate_setting, usb_string_finder)?);
		}
		
		debug_assert!(interface_alternate_settings.len() > 0, "No interface alternate settings");
		
		Ok(interface_alternate_settings)
	}
}
