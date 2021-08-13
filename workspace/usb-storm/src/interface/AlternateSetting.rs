// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An USB interface alternate setting.
///
/// Represents an Interface Descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlternateSetting
{
	interface_class: InterfaceClass,

	description: Option<LocalizedStrings>,
	
	additional_descriptors: Vec<Descriptor<InterfaceAdditionalDescriptor>>,

	end_points: WrappedIndexMap<EndPointNumber, EndPoint>,
}

impl AlternateSetting
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn interface_class(&self) -> InterfaceClass
	{
		self.interface_class
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
	pub fn additional_descriptors(&self) -> &[Descriptor<InterfaceAdditionalDescriptor>]
	{
		&self.additional_descriptors
	}
	
	// #[inline(always)]
	// fn smart_card_interface_additional_descriptor(&self) -> Option<&SmartCardInterfaceAdditionalDescriptor>
	// {
	// 	for additional_descriptor in self.descriptors.iter()
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
	fn parse(string_finder: &StringFinder, alternate_setting: &libusb_interface_descriptor, interface_index: u8, alternate_setting_index: u8, maximum_supported_usb_version: Version) -> Result<DeadOrAlive<(InterfaceNumber, AlternateSettingNumber, Self)>, AlternateSettingParseError>
	{
		use AlternateSettingParseError::*;

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
		
		let interface_class = InterfaceClass::parse(alternate_setting);
		let end_point_descriptors = Self::parse_end_point_descriptors(alternate_setting, interface_index, alternate_setting_index)?;
		let description = string_finder.find_string(alternate_setting.iInterface).map_err(|cause| DescriptionString { cause, interface_index, alternate_setting_index })?;
		let additional_descriptors = Self::parse_additional_descriptors(alternate_setting, interface_class, string_finder).map_err(|cause| CouldNotParseAlternateSettingAdditionalDescriptor { cause, interface_index, alternate_setting_index })?;
		let end_points = Self::parse_end_points(end_point_descriptors, interface_index, alternate_setting_index, maximum_supported_usb_version, string_finder)?;
		Ok
		(
			Alive
			(
				(
					bInterfaceNumber,
					
					alternate_setting.bAlternateSetting,
					
					Self
					{
						interface_class,
						
						description: return_ok_if_dead!(description),
						
						additional_descriptors: return_ok_if_dead!(additional_descriptors),
						
						end_points: return_ok_if_dead!(end_points),
					}
				)
			)
		)
	}
	
	#[inline(always)]
	fn parse_end_points(end_point_descriptors: &[libusb_endpoint_descriptor], interface_index: u8, alternate_setting_index: u8, maximum_supported_usb_version: Version, string_finder: &StringFinder) -> Result<DeadOrAlive<WrappedIndexMap<EndPointNumber, EndPoint>>, AlternateSettingParseError>
	{
		use AlternateSettingParseError::*;
		
		let mut end_points = WrappedIndexMap::with_capacity(end_point_descriptors.len()).map_err(CouldNotAllocateMemoryForEndPoints)?;
		
		for end_point_index in 0 .. (end_points.len() as u5)
		{
			let end_point_descriptor = end_point_descriptors.get_unchecked_safe(end_point_index);
			let parsed = EndPoint::parse(end_point_descriptor, maximum_supported_usb_version, string_finder).map_err(|cause| EndPointParse { cause, interface_index, alternate_setting_index, end_point_index })?;
			let (end_point_number, end_point) = return_ok_if_dead!(parsed);
			
			let outcome = end_points.insert(end_point_number, end_point);
			if unlikely!(outcome.is_some())
			{
				return Err(DuplicateEndPointNumber { interface_index, alternate_setting_index, end_point_index, end_point_number })
			}
		}
		
		Ok(Alive(end_points))
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
	fn parse_additional_descriptors(alternate_setting: &libusb_interface_descriptor, interface_class: InterfaceClass, string_finder: &StringFinder) -> Result<DeadOrAlive<Vec<Descriptor<InterfaceAdditionalDescriptor>>>, DescriptorParseError<InterfaceAdditionalDescriptorParseError>>
	{
		#[inline(always)]
		fn device_upgrade_firmware(string_finder: &StringFinder, extra: &[u8]) -> Result<DeadOrAlive<Vec<Descriptor<InterfaceAdditionalDescriptor>>>, DescriptorParseError<InterfaceAdditionalDescriptorParseError>>
		{
			InterfaceAdditionalDescriptorParser::parse_additional_descriptors(string_finder, extra, DeviceFirmwareUpgradeInterfaceAdditionalDescriptorParser)
		}
		
		#[inline(always)]
		fn human_interface_device(string_finder: &StringFinder, extra: &[u8], variant: HumanInterfaceDeviceInterfaceAdditionalVariant) -> Result<DeadOrAlive<Vec<Descriptor<InterfaceAdditionalDescriptor>>>, DescriptorParseError<InterfaceAdditionalDescriptorParseError>>
		{
			InterfaceAdditionalDescriptorParser::parse_additional_descriptors(string_finder, extra, HumanInterfaceDeviceInterfaceAdditionalDescriptorParser::new(variant))
		}
		
		#[inline(always)]
		fn smart_card(string_finder: &StringFinder, extra: &[u8], smart_card_protocol: SmartCardProtocol, bDescriptorType: u8) -> Result<DeadOrAlive<Vec<Descriptor<InterfaceAdditionalDescriptor>>>, DescriptorParseError<InterfaceAdditionalDescriptorParseError>>
		{
			InterfaceAdditionalDescriptorParser::parse_additional_descriptors(string_finder, extra, SmartCardInterfaceAdditionalDescriptorParser::new(smart_card_protocol, bDescriptorType))
		}
		
		#[inline(always)]
		fn unsupported_smart_card_with_descriptor_at_end_of_end_points(string_finder: &StringFinder, extra: &[u8]) -> Result<DeadOrAlive<Vec<Descriptor<InterfaceAdditionalDescriptor>>>, DescriptorParseError<InterfaceAdditionalDescriptorParseError>>
		{
			unsupported(string_finder, extra)
		}
		
		#[inline(always)]
		fn unsupported(string_finder: &StringFinder, extra: &[u8]) -> Result<DeadOrAlive<Vec<Descriptor<InterfaceAdditionalDescriptor>>>, DescriptorParseError<InterfaceAdditionalDescriptorParseError>>
		{
			InterfaceAdditionalDescriptorParser::parse_additional_descriptors(string_finder, extra, UnsupportedInterfaceAdditionalDescriptorParser)
		}
		
		use HumanInterfaceDeviceInterfaceAdditionalVariant::*;
		
		let extra = extra_to_slice(alternate_setting.extra, alternate_setting.extra_length)?;
		
		use ApplicationSpecificInterfaceSubClass::DeviceFirmwareUpgrade;
		use HumanInterfaceDeviceInterfaceBootProtocol::Keyboard;
		use HumanInterfaceDeviceInterfaceBootProtocol::Mouse;
		use HumanInterfaceDeviceInterfaceSubClass::Boot;
		use InterfaceClass::*;
		use SmartCardProtocol::*;
		
		const SmartCardDescriptorType: u8 = 0x21;
		const VendorSpecificDescriptorType: u8 = 0xFF;
		
		match interface_class
		{
			ApplicationSpecific(DeviceFirmwareUpgrade(KnownOrUnrecognizedProtocol::Known)) => device_upgrade_firmware(string_finder, extra),
			
			HumanInterfaceDevice(HumanInterfaceDeviceInterfaceSubClass::None { unknown_protocol: None }) => human_interface_device(string_finder, extra, NotBoot),
			HumanInterfaceDevice(Boot(HumanInterfaceDeviceInterfaceBootProtocol::None)) => human_interface_device(string_finder, extra, BootNone),
			HumanInterfaceDevice(Boot(Keyboard)) => human_interface_device(string_finder, extra, BootKeyboard),
			HumanInterfaceDevice(Boot(Mouse)) => human_interface_device(string_finder, extra, BootMouse),
			
			// Some devices from as far back as 2007 put the Smart Card descriptor at the end of the end points yet claim to be a Smart Card.
			// The CCID project uses a patch with `#define O2MICRO_OZ776_PATCH` to support them; they are broken in use in multiple ways.
			// We do not support them.
			//
			// Devices known to be problematic include the:-
			//
			// * O2Micro CCID SC Reader (0x0B97, 0x7762, 2004).
			// * O2Micro CCID SC Reader (0x0B97, 0x7772, 2007).
			// * BLUDRIVE II CCID (0x1B0E, 0x1078, 2008).
			// * <No product name> (0x1B0E, 0x1079, 2015).
			//
			// * The sub class is 0x00.
			// * The protocol is always 0x00.
			// * The bDescriptorType is 0x21 (standard).
			//
			// Notes:-
			// * \* Does not have a manufacturer or product name string, but known as 'Blutronics Bludrive II' or 'BludriveIIv2.txt' in the CCID project; the unversioned original driver dates from 2008 and is called 'BLUDRIVE II CCID'.
			SmartCard(SmartCardInterfaceSubClass::Known(BulkTransfer)) if extra.is_empty() => unsupported_smart_card_with_descriptor_at_end_of_end_points(string_finder, extra),
			
			SmartCard(SmartCardInterfaceSubClass::Known(BulkTransfer)) => smart_card(string_finder, extra, BulkTransfer, SmartCardDescriptorType),
			SmartCard(SmartCardInterfaceSubClass::Known(IccdVersionA)) => smart_card(string_finder, extra, IccdVersionA, SmartCardDescriptorType),
			SmartCard(SmartCardInterfaceSubClass::Known(IccdVersionB)) => smart_card(string_finder, extra, IccdVersionB, SmartCardDescriptorType),
			
			// Product Name (Vendor Identifier, Product Identifier, Year Added to CCID).
			// * USB Reader V2 (0x09C3, 0x0008, 2006).
			//
			// The bDescriptorType is 0x21.
			SmartCard(SmartCardInterfaceSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code: 0x01, protocol_code: 0x01 })) if SmartCardInterfaceAdditionalDescriptor::extra_has_matching_length(extra) => smart_card(string_finder, extra, IccdVersionA, SmartCardDescriptorType),
			
			// These pre-standardization devices have the following features:-
			//
			// * The sub class is 0x5C.
			// * The protocol is always 0x00.
			// * The bDescriptorType is 0xFF.
			//
			// Product Name (Vendor Identifier, Product Identifier, Year Added to CCID).
			// * Dell USB Smartcard Keyboard (0x413C, 0x2100, 2004).
			// * Gem e-Seal Pro USB Token (0x08E6, 0x2202, 2008).
			// * MySMART PAD V2.0 (0x09BE, 0x0002, 2005).
			// * Token GEM USB COMBI (0x08E6, 0xACE0, 2005).
			// * Token GEM USB COMBI-M (0x08E6, 0x1359, 2005).
			VendorSpecific(UnrecognizedSubClass { sub_class_code: 0x5C, protocol_code: 0x00 }) if SmartCardInterfaceAdditionalDescriptor::extra_has_matching_length(extra) => smart_card(string_finder, extra, BulkTransfer, VendorSpecificDescriptorType),
			
			// This case exists from before standardization; devices have the following features:-
			//
			// * The sub class is 0x00.
			// * The protocol is always 0x00 ..= 0x02.
			// * The bDescriptorType is 0x21 (standard).
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
			VendorSpecific(UnrecognizedSubClass { sub_class_code: 0x00, protocol_code: 0x00 }) if SmartCardInterfaceAdditionalDescriptor::extra_has_matching_length(extra) => smart_card(string_finder, extra, BulkTransfer, SmartCardDescriptorType),
			VendorSpecific(UnrecognizedSubClass { sub_class_code: 0x00, protocol_code: 0x01 }) if SmartCardInterfaceAdditionalDescriptor::extra_has_matching_length(extra) => smart_card(string_finder, extra, IccdVersionA, SmartCardDescriptorType),
			VendorSpecific(UnrecognizedSubClass { sub_class_code: 0x00, protocol_code: 0x02 }) if SmartCardInterfaceAdditionalDescriptor::extra_has_matching_length(extra) => smart_card(string_finder, extra, IccdVersionB, SmartCardDescriptorType),
			
			// Some devices from as far back as 2007 put the Smart Card descriptor at the end of the end points.
			// The CCID project uses a patch with `#define O2MICRO_OZ776_PATCH` to support them; they are broken in use in multiple ways.
			// We do not support them.
			//
			// Devices known to be problematic include the:-
			//
			// * cyberJack pinpad(a) (0x0C4B, 0x0300, 2007), 0x21.
			// * cyberJack RFID standard (0x0C4B, 0x0500, 2017), 0x21.
			//
			// * The sub class is 0x00.
			// * The protocol is always 0x00.
			// * The bDescriptorType is 0x21 (standard).
			VendorSpecific(UnrecognizedSubClass { sub_class_code: 0x00, protocol_code: 0x00 }) if extra.is_empty() => unsupported_smart_card_with_descriptor_at_end_of_end_points(string_finder, extra),
			
			_ => unsupported(string_finder, extra),
		}
	}
}
