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
	
	class_and_protocol: UsbClassAndProtocol<Interface>,

	description: Option<UsbStringOrIndex>,

	end_points: IndexMap<EndPointNumber, UsbEndPoint>,
	
	additional_descriptors: Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>,
}

impl UsbInterfaceAlternateSetting
{
	#[inline(always)]
	fn smart_card_interface_additional_descriptor(&self) -> Option<&SmartCardInterfaceAdditionalDescriptor>
	{
		for additional_descriptor in self.additional_descriptors.iter()
		{
			use self::AdditionalDescriptor::*;
			use self::InterfaceAdditionalDescriptor::*;
			if let Known(SmartCard(smart_card_interface_additional_descriptor)) = additional_descriptor
			{
				return Some(smart_card_interface_additional_descriptor)
			}
		}
		None
	}
	
	#[inline(always)]
	fn try_from(interface_descriptor: InterfaceDescriptor, usb_string_finder: &UsbStringFinder<impl UsbContext>) -> Result<Self, UsbError>
	{
		let class_and_protocol = UsbClassAndProtocol::new_from_interface(&interface_descriptor);
		
		let (additional_descriptors, strip_last_end_point_of_extra) = Self::parse_additional_descriptors(&interface_descriptor, class_and_protocol);
		let additional_descriptors = additional_descriptors?;
		
		Ok
		(
			Self
			{
				alternate_setting_number: interface_descriptor.setting_number(),
				
				class_and_protocol,
				
				description: usb_string_finder.find(interface_descriptor.description_string_index())?,
			
				additional_descriptors,
				
				end_points: UsbEndPoint::usb_end_points_from(interface_descriptor, strip_last_end_point_of_extra)?,
			}
		)
	}
	
	#[inline(always)]
	fn usb_interface_alternate_settings_try_from(interface: rusb::Interface, usb_string_finder: &UsbStringFinder<impl UsbContext>) -> Result<Vec<Self>, UsbError>
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
	
	#[inline(always)]
	fn parse_additional_descriptors(interface_descriptor: &InterfaceDescriptor, class_and_protocol: UsbClassAndProtocol<Interface>) -> (Result<Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>, AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>>, Option<EndPointNumber>)
	{
		#[inline(always)]
		fn human_interface_device(extra: Option<&[u8]>, variant: HumanInterfaceDeviceInterfaceAdditionalVariant) -> (Result<Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>, AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>>, Option<EndPointNumber>)
		{
			(InterfaceAdditionalDescriptorParser::parse_additional_descriptors(extra, HumanInterfaceDeviceInterfaceAdditionalDescriptorParser::new(variant)), None)
		}
		
		#[inline(always)]
		fn smart_card(extra: Option<&[u8]>, raw_protocol: u8, strip_last_end_point_of_extra: Option<EndPointNumber>) -> (Result<Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>, AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>>, Option<EndPointNumber>)
		{
			let smart_card_protocol = unsafe { transmute(raw_protocol) };
			(InterfaceAdditionalDescriptorParser::parse_additional_descriptors(extra, SmartCardInterfaceAdditionalDescriptorParser::new(smart_card_protocol)), strip_last_end_point_of_extra)
		}
		
		#[inline(always)]
		fn unsupported(extra: Option<&[u8]>) -> (Result<Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>, AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>>, Option<EndPointNumber>)
		{
			(InterfaceAdditionalDescriptorParser::parse_additional_descriptors(extra, UnsupportedInterfaceAdditionalDescriptorParser), None)
		}
		
		use self::HumanInterfaceDeviceInterfaceAdditionalVariant::*;
		let extra = interface_descriptor.extra();
		match class_and_protocol.codes()
		{
			(Interface::HumanInterfaceDeviceClass, Interface::HumanInterfaceDeviceNoSubClass, 0x00) => human_interface_device(extra, NotBoot),
			(Interface::HumanInterfaceDeviceClass, Interface::HumanInterfaceDeviceBootInterfaceSubClass, Interface::HumanInterfaceDeviceBootInterfaceNoneProtocol) => human_interface_device(extra, BootNone),
			(Interface::HumanInterfaceDeviceClass, Interface::HumanInterfaceDeviceBootInterfaceSubClass, Interface::HumanInterfaceDeviceBootInterfaceKeyboardProtocol) => human_interface_device(extra, BootKeyboard),
			(Interface::HumanInterfaceDeviceClass, Interface::HumanInterfaceDeviceBootInterfaceSubClass, Interface::HumanInterfaceDeviceBootInterfaceMouseProtocol) => human_interface_device(extra, BootMouse),
			
			(Interface::SmartCardClass, 0x00, raw_protocol @ 0x00 ..= 0x02) => smart_card(extra, raw_protocol, None),
			
			(Interface::VendorSpecificClass, 0x00, raw_protocol @ 0x00 ..= 0x02) => if SmartCardInterfaceAdditionalDescriptor::extra_has_matching_length(extra)
			{
				// This case exists from before standardization.
				smart_card(extra, raw_protocol, None)
			}
			else if extra.is_none()
			{
				// Devices such as the O2 Micro Oz776, REINER SCT (aka Reiner-SCT and Reiner SCT) and Blutronics Bludrive II (aka bludrive) put the Smart Card interface descriptor at the end of the end points as an End Point descriptor.
				// That said, these devices are now very rare (they existed at least as far back as 2010).
				// However, we do not know if other device manufacturers do this curently.
				// The O2 Micro Oz776 is broken in other ways - see the patch introduced in the CCID project with `#define O2MICRO_OZ776_PATCH`.
				if let Some(legacy_with_descriptor_in_last_end_point) = SmartCardInterfaceAdditionalDescriptor::last_end_point_matches(interface_descriptor, |extra, last_end_point_number| smart_card(Some(extra), raw_protocol, Some(last_end_point_number)))
				{
					legacy_with_descriptor_in_last_end_point
				}
				else
				{
					unsupported(None)
				}
			}
			else
			{
				unsupported(extra)
			},
			
			_ => unsupported(extra),
		}
	}
}
