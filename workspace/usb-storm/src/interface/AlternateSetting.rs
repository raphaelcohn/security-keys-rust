// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An USB interface alternate setting.
///
/// Represents an Interface Descriptor.
#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlternateSetting
{
	class_and_protocol: ClassAndProtocol<AlternateSetting>,

	description: Option<StringOrIndex>,
	
	additional_descriptors: Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>,

	end_points: IndexMap<EndPointNumber, EndPoint>,
}

impl DeviceOrAlternateSetting for AlternateSetting
{
}

impl AlternateSetting
{
	/// Alternate setting number.
	#[inline(always)]
	pub const fn alternate_setting_number(&self) -> u8
	{
		self.alternate_setting_number
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn class_and_protocol(&self) -> ClassAndProtocol<AlternateSetting>
	{
		self.class_and_protocol
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn description(&self) -> Option<&StringOrIndex>
	{
		self.description.as_ref()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn end_points(&self) -> &IndexMap<EndPointNumber, EndPoint>
	{
		&self.end_points
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn additional_descriptors(&self) -> &[AdditionalDescriptor<InterfaceAdditionalDescriptor>]
	{
		&self.additional_descriptors
	}
	
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
	fn parse(string_finder: &StringFinder, alternate_setting: &libusb_interface_descriptor, interface_index: u8, alternate_setting_index: u8) -> Result<(InterfaceNumber, AlternateSettingNumber, Self), AlternateSettingParseError>
	{
		use self::AlternateSettingParseError::*;
		
		const LIBUSB_DT_INTERFACE_SIZE: usize = 9;
		let bLength = alternate_setting.bLength;
		if unlikely!(bLength < LIBUSB_DT_INTERFACE_SIZE)
		{
			return Err(WrongLength { interface_index, alternate_setting_index, bLength })
		}
		
		let bDescriptorType = alternate_setting.bDescriptorType;
		if unlikely!(bDescriptorType != LIBUSB_DT_INTERFACE)
		{
			return Err(WrongDescriptorType { interface_index, alternate_setting_index, bDescriptorType })
		}
		
		let bInterfaceNumber = alternate_setting.bInterfaceNumber;
		if unlikely!(bInterfaceNumber >= MaximumNumberOfInterfaces)
		{
			Err(InterfaceNumberTooLarge { interface_index, alternate_setting_index, bInterfaceNumber })
		}
		
		let class_and_protocol = ClassAndProtocol::new_from_alternate_setting(alternate_setting);
		
		let end_point_descriptors = Self::parse_end_point_descriptors(alternate_setting, interface_index, alternate_setting_index)?;
		
		let (additional_descriptors, strip_last_end_point_of_extra) = Self::parse_additional_descriptors(interface_descriptor, class_and_protocol);
		let additional_descriptors = additional_descriptors?;
		
		Ok
		(
			(
				bInterfaceNumber,
				
				alternate_setting.bAlternateSetting,
				
				Self
				{
					class_and_protocol,
					
					description: string_finder.find_string(alternate_setting.iInterface)?,
					
					additional_descriptors,
					
					end_points: Self::parse_end_points(end_point_descriptors, interface_index, alternate_setting_index)?,
				}
			)
		)
	}
	
	#[inline(always)]
	fn parse_end_points(end_point_descriptors: &[libusb_endpoint_descriptor], interface_index: u8, alternate_setting_index: u8) -> Result<IndexMap<EndPointNumber, EndPoint>, AlternateSettingParseError>
	{
		use self::AlternateSettingParseError::*;
		
		let mut end_points = IndexMap::with_capacity(end_point_descriptors.len());
		
		for end_point_index in 0 .. (end_points.len() as u5)
		{
			let end_point_descriptor = end_point_descriptors.get_unchecked_safe(end_point_index);
			let (end_point_number, end_point) = EndPoint::parse(end_point_descriptor).map_err(|cause| EndPointParse { cause, interface_index, alternate_setting_index, end_point_index })?;
			
			let outcome = end_points.insert(end_point_number, end_point);
			if unlikely!(outcome.is_some())
			{
				return Err(DuplicateEndPointNumber { interface_index, alternate_setting_index, end_point_index, end_point_number })
			}
		}
		
		Ok(end_points)
	}
	
	#[inline(always)]
	fn parse_end_point_descriptors(alternate_setting: &libusb_interface_descriptor, interface_index: u8, alternate_setting_index: u8) -> Result<&[libusb_endpoint_descriptor], AlternateSettingParseError>
	{
		use self::AlternateSettingParseError::*;
		
		let end_pointer_pointer = alternate_setting.endpoint;
		if unlikely!(end_pointer_pointer.is_null())
		{
			return Err(EndPointsPointerIsNull { interface_index, alternate_setting_index })
		}
		
		let bNumEndpoints = alternate_setting.bNumEndpoints;
		if unlikely!(bNumEndpoints > InclusiveMaximumNumberOfEndPoints)
		{
			return Err(TooManyEndPoints { interface_index, alternate_setting_index, bNumEndpoints  })
		}
		
		Ok(unsafe { from_raw_parts(end_pointer_pointer, bNumEndpoints as usize) })
	}
	
	#[inline(always)]
	fn parse_additional_descriptors(alternate_setting: &libusb_interface_descriptor, class_and_protocol: ClassAndProtocol<Self>) -> (Result<Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>, AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>>, Option<EndPointNumber>)
	{
		#[inline(always)]
		fn human_interface_device(extra: &[u8], variant: HumanInterfaceDeviceInterfaceAdditionalVariant) -> (Result<Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>, AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>>, Option<EndPointNumber>)
		{
			(InterfaceAdditionalDescriptorParser::parse_additional_descriptors(extra, HumanInterfaceDeviceInterfaceAdditionalDescriptorParser::new(variant)), None)
		}
		
		#[inline(always)]
		fn smart_card(extra: &[u8], raw_protocol: u8, strip_last_end_point_of_extra: Option<EndPointNumber>) -> (Result<Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>, AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>>, Option<EndPointNumber>)
		{
			let smart_card_protocol = unsafe { transmute(raw_protocol) };
			(InterfaceAdditionalDescriptorParser::parse_additional_descriptors(extra, SmartCardInterfaceAdditionalDescriptorParser::new(smart_card_protocol)), strip_last_end_point_of_extra)
		}
		
		#[inline(always)]
		fn unsupported(extra: &[u8]) -> (Result<Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>, AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>>, Option<EndPointNumber>)
		{
			(InterfaceAdditionalDescriptorParser::parse_additional_descriptors(extra, UnsupportedInterfaceAdditionalDescriptorParser), None)
		}
		
		use self::HumanInterfaceDeviceInterfaceAdditionalVariant::*;
		
		let extra = extra_to_slice(alternate_setting.extra, alternate_setting.extra_length)?;
		
		match class_and_protocol.codes()
		{
			(ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceClass, ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceNoSubClass, 0x00) => human_interface_device(extra, NotBoot),
			(ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceClass, ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceBootInterfaceSubClass, ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceBootInterfaceNoneProtocol) => human_interface_device(extra, BootNone),
			(ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceClass, ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceBootInterfaceSubClass, ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceBootInterfaceKeyboardProtocol) => human_interface_device(extra, BootKeyboard),
			(ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceClass, ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceBootInterfaceSubClass, ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceBootInterfaceMouseProtocol) => human_interface_device(extra, BootMouse),
			
			(ClassAndProtocol::<AlternateSetting>::SmartCardClass, 0x00, raw_protocol @ 0x00 ..= 0x02) => smart_card(extra, raw_protocol, None),
			
			// This case exists from before standardization.
			(ClassAndProtocol::<AlternateSetting>::VendorSpecificClass, 0x00, raw_protocol @ 0x00 ..= 0x02) if SmartCardInterfaceAdditionalDescriptor::extra_has_matching_length(extra) => smart_card(extra, raw_protocol, None),
			
			// Devices such as the O2 Micro Oz776, REINER SCT (aka Reiner-SCT and Reiner SCT) and Blutronics Bludrive II (aka bludrive) put the Smart Card descriptor at the end of the end points.
			// That said, these devices are now very rare (they existed at least as far back as 2007).
			// However, we do not know if other device manufacturers do this curently.
			// The O2 Micro Oz776 is broken in other ways - see the patch introduced in the CCID project with `#define O2MICRO_OZ776_PATCH`.
			// We do not support them here.
			(ClassAndProtocol::<AlternateSetting>::VendorSpecificClass, 0x00, raw_protocol @ 0x00 ..= 0x02) if extra.len() == 0 => unsupported(extra),
			
			_ => unsupported(extra),
		}
	}
}
