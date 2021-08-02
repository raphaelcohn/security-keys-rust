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

	description: Option<LocalizedStrings>,
	
	additional_descriptors: Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>,

	end_points: IndexMap<EndPointNumber, EndPoint>,
}

impl DeviceOrAlternateSetting for AlternateSetting
{
}

impl AlternateSetting
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn class_and_protocol(&self) -> ClassAndProtocol<AlternateSetting>
	{
		self.class_and_protocol.clone()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn description(&self) -> Option<&LocalizedStrings>
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
	
	// #[inline(always)]
	// fn smart_card_interface_additional_descriptor(&self) -> Option<&SmartCardInterfaceAdditionalDescriptor>
	// {
	// 	for additional_descriptor in self.additional_descriptors.iter()
	// 	{
	// 		use AdditionalDescriptor::*;
	// 		use InterfaceAdditionalDescriptor::*;
	// 		if let Known(SmartCard(smart_card_interface_additional_descriptor)) = additional_descriptor
	// 		{
	// 			return Some(smart_card_interface_additional_descriptor)
	// 		}
	// 	}
	// 	None
	// }
	
	#[inline(always)]
	fn parse(string_finder: &StringFinder, alternate_setting: &libusb_interface_descriptor, interface_index: u8, alternate_setting_index: u8) -> Result<DeadOrAlive<(InterfaceNumber, AlternateSettingNumber, Self)>, AlternateSettingParseError>
	{
		use AlternateSettingParseError::*;
		use DeadOrAlive::*;
		
		const LIBUSB_DT_INTERFACE_SIZE: u8 = 9;
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
			return Err(InterfaceNumberTooLarge { interface_index, alternate_setting_index, bInterfaceNumber })
		}
		
		let class_and_protocol = ClassAndProtocol::new_from_alternate_setting(alternate_setting);
		
		let end_point_descriptors = Self::parse_end_point_descriptors(alternate_setting, interface_index, alternate_setting_index)?;
		
		let additional_descriptors = Self::parse_additional_descriptors(alternate_setting, class_and_protocol.clone()).map_err(|cause| CouldNotParseAlternateSettingAdditionalDescriptor { cause, interface_index, alternate_setting_index })?;
		
		Ok
		(
			Alive
			(
				(
					bInterfaceNumber,
					
					alternate_setting.bAlternateSetting,
					
					Self
					{
						class_and_protocol,
						
						description: match string_finder.find_string(alternate_setting.iInterface).map_err(|cause| DescriptionString { cause, interface_index, alternate_setting_index })?
						{
							Dead => return Ok(Dead),
							
							Alive(description) => description,
						},
						
						additional_descriptors,
						
						end_points: Self::parse_end_points(end_point_descriptors, interface_index, alternate_setting_index)?,
					}
				)
			)
		)
	}
	
	#[inline(always)]
	fn parse_end_points(end_point_descriptors: &[libusb_endpoint_descriptor], interface_index: u8, alternate_setting_index: u8) -> Result<IndexMap<EndPointNumber, EndPoint>, AlternateSettingParseError>
	{
		use AlternateSettingParseError::*;
		
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
		use AlternateSettingParseError::*;
		
		let bNumEndpoints = alternate_setting.bNumEndpoints;
		if unlikely!(bNumEndpoints > InclusiveMaximumNumberOfEndPoints)
		{
			return Err(TooManyEndPoints { interface_index, alternate_setting_index, bNumEndpoints  })
		}
		
		let end_pointer_pointer = alternate_setting.endpoint;
		if unlikely!(end_pointer_pointer.is_null())
		{
			if unlikely!(bNumEndpoints != 0)
			{
				return Err(EndPointsPointerIsNullBuNumberOfEndPointsIsNotZero { interface_index, alternate_setting_index, bNumEndpoints })
			}
			
			Ok(unsafe { from_raw_parts(NonNull::dangling().as_ptr() as *const _, 0) })
		}
		else
		{
			Ok(unsafe { from_raw_parts(end_pointer_pointer, bNumEndpoints as usize) })
		}
	}
	
	#[inline(always)]
	fn parse_additional_descriptors(alternate_setting: &libusb_interface_descriptor, class_and_protocol: ClassAndProtocol<Self>) -> Result<Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>, AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>>
	{
		#[inline(always)]
		fn human_interface_device(extra: &[u8], variant: HumanInterfaceDeviceInterfaceAdditionalVariant) -> Result<Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>, AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>>
		{
			InterfaceAdditionalDescriptorParser::parse_additional_descriptors(extra, HumanInterfaceDeviceInterfaceAdditionalDescriptorParser::new(variant))
		}
		
		#[inline(always)]
		fn smart_card(extra: &[u8], raw_protocol: u8) -> Result<Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>, AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>>
		{
			let smart_card_protocol = unsafe { transmute(raw_protocol) };
			InterfaceAdditionalDescriptorParser::parse_additional_descriptors(extra, SmartCardInterfaceAdditionalDescriptorParser::new(smart_card_protocol))
		}
		
		#[inline(always)]
		fn unsupported(extra: &[u8]) -> Result<Vec<AdditionalDescriptor<InterfaceAdditionalDescriptor>>, AdditionalDescriptorParseError<InterfaceAdditionalDescriptorParseError>>
		{
			InterfaceAdditionalDescriptorParser::parse_additional_descriptors(extra, UnsupportedInterfaceAdditionalDescriptorParser)
		}
		
		use HumanInterfaceDeviceInterfaceAdditionalVariant::*;
		
		let extra = extra_to_slice(alternate_setting.extra, alternate_setting.extra_length)?;
		
		match class_and_protocol.codes()
		{
			(ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceClass, ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceNoSubClass, 0x00) => human_interface_device(extra, NotBoot),
			(ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceClass, ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceBootInterfaceSubClass, ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceBootInterfaceNoneProtocol) => human_interface_device(extra, BootNone),
			(ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceClass, ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceBootInterfaceSubClass, ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceBootInterfaceKeyboardProtocol) => human_interface_device(extra, BootKeyboard),
			(ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceClass, ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceBootInterfaceSubClass, ClassAndProtocol::<AlternateSetting>::HumanInterfaceDeviceBootInterfaceMouseProtocol) => human_interface_device(extra, BootMouse),
			
			(ClassAndProtocol::<AlternateSetting>::SmartCardClass, 0x00, raw_protocol @ 0x00 ..= 0x02) => smart_card(extra, raw_protocol),
			
			// Product Name (Vendor Identifier, Product Identifier, Year Added to CCID) Descriptor Type.
			// ActivCard USB Reader V2 (0x09C3, 0x0008, 2006) 0x21.
			(ClassAndProtocol::<AlternateSetting>::SmartCardClass, 0x01, raw_protocol @ 0x01) if SmartCardInterfaceAdditionalDescriptor::extra_has_matching_length(extra) => smart_card(extra, raw_protocol),
			
			// These pre-standardization devices have the following features:-
			//
			// * The bDescriptorType is 0xFF;
			// * The sub class is 0x5C;
			// * The protocol is always 0x00.
			//
			// Product Name (Vendor Identifier, Product Identifier, Year Added to CCID).
			// * Dell USB Smartcard Keyboard (0x413C, 0x2100, 2004).
			// * Gem e-Seal Pro USB Token (0x08E6, 0x2202, 2008).
			// * MySMART PAD V2.0 (0x09BE, 0x0002, 2005).
			// * Token GEM USB COMBI (0x08E6, 0xACE0, 2005).
			// * Token GEM USB COMBI-M (0x08E6, 0x1359, 2005).
			(ClassAndProtocol::<AlternateSetting>::VendorSpecificClass, 0x5C, raw_protocol @ 0x00) if SmartCardInterfaceAdditionalDescriptor::extra_has_matching_length(extra) => smart_card(extra, raw_protocol),
			
			// This case exists from before standardization.
			//
			// Product Name (Vendor Identifier, Product Identifier, Year Added to CCID).
			// * SchlumbergerSema Cyberflex Access (0x0973, 0x0003, 2007).
			// * SmartTerminal ST-2xxx (0x046A, 0x003E, 2005).
			// * DE-ABCM6 (0x1DB2, 0x0600, 2016)†.
			// * Smart Card Reader USB (0x076B, 0x5340, 2016)‡.
			// * USB Smart Chip Device (0x1A74, 0x6354, 2008).
			// * USB Smart Chip Device (0x1A74, 0x6356, 2009).
			// * Smart Card Reader USB (0x076B, 0x532A, 2017)†.
			// * SCL010 Contactless Reader (0x04E6, 0x5291, 2009).
			// * SCL01x Contactless Reader (0x04E6, 0x5292, 2010).
			// * SDI011 Contactless Reader (0x04E6, 0x512B, 2011).
			// * SDI011 Contactless Reader (0x04E6, 0x512C, 2013).
			// * SCR331-DI USB Smart Card Reader (0x04E6, 0x5120, 2005).
			// * SCR331-DI USB Smart Card Reader (0x04E6, 0x5111, 2004).
			// * SCR3310-NTTCom USB SmartCard Reader (0x04E6, 0x511A, 2012\*).
			// * SDI010 Smart Card Reader (0x04E6, 0x5121, 2006).
			// * SPRx32 USB Smart Card Reader (0x04E6, 0xE003, 2003).
			//
			// Notes:-
			// * \* Re-added.
			// * †Disabled in CCID.
			// * ‡Multiple interfaces.
			(ClassAndProtocol::<AlternateSetting>::VendorSpecificClass, 0x00, raw_protocol @ 0x00 ..= 0x02) if SmartCardInterfaceAdditionalDescriptor::extra_has_matching_length(extra) => smart_card(extra, raw_protocol),
			
			// Some devices from as far back as 2007 put the Smart Card descriptor at the end of the end points.
			// Devices known to be problematic include the:-
			//
			// * cyberJack pinpad(a) (0x0C4B, 0x0300, 2007), 0x21.
			// * cyberJack RFID standard (0x0C4B, 0x0500, 2017), 0x21.
			// * O2 Micro Oz776 (0x0B97, 0x7762).
			// * O2 Micro Oz776 (0x0B97, 0x7772).
			// * Blutronics Bludrive II (aka bludrive) (?, ?).
			//
			// The CCID project uses a patch with `#define O2MICRO_OZ776_PATCH` to support them; they are broken in multiple ways.
			// We do not support them here.
			(ClassAndProtocol::<AlternateSetting>::VendorSpecificClass, 0x00, _raw_protocol @ 0x00 ..= 0x02) if extra.len() == 0 => unsupported(extra),
			
			_ => unsupported(extra),
		}
	}
}
