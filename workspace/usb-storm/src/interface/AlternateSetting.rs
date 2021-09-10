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
	
	descriptors: Vec<InterfaceExtraDescriptor>,

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
	pub fn descriptors(&self) -> &[InterfaceExtraDescriptor]
	{
		&self.descriptors
	}
	
	#[inline(always)]
	fn parse(device_connection: &DeviceConnection, reusable_buffer: &mut ReusableBuffer, alternate_setting: &libusb_interface_descriptor, interface_index: u8, alternate_setting_index: u8, maximum_supported_usb_version: Version, speed: Option<Speed>) -> Result<DeadOrAlive<(InterfaceNumber, AlternateSettingNumber, Self)>, AlternateSettingParseError>
	{
		use AlternateSettingParseError::*;
		
		{
			const LIBUSB_DT_INTERFACE_SIZE: u8 = 9;
			let bLength = alternate_setting.bLength;
			if unlikely!(bLength < LIBUSB_DT_INTERFACE_SIZE)
			{
				return Err(WrongLength { interface_index, alternate_setting_index, bLength })
			}
		}
		
		{
			let bDescriptorType = alternate_setting.bDescriptorType;
			if unlikely!(bDescriptorType != LIBUSB_DT_INTERFACE)
			{
				return Err(WrongDescriptorType { interface_index, alternate_setting_index, bDescriptorType })
			}
		}
		
		let interface_number =
		{
			let bInterfaceNumber = alternate_setting.bInterfaceNumber;
			if unlikely!(bInterfaceNumber >= MaximumNumberOfInterfaces)
			{
				return Err(InterfaceNumberTooLarge { interface_index, alternate_setting_index, bInterfaceNumber })
			}
			bInterfaceNumber
		};
		
		let interface_class = InterfaceClass::parse(alternate_setting);
		Ok
		(
			Alive
			(
				(
					interface_number,
					
					alternate_setting.bAlternateSetting,
					
					Self
					{
						interface_class,
						
						description:
						{
							let description = device_connection.find_string(alternate_setting.iInterface).map_err(|cause| DescriptionString { cause, interface_index, alternate_setting_index })?;
							return_ok_if_dead!(description)
						},
						
						descriptors:
						{
							let descriptors = Self::parse_descriptors(alternate_setting, interface_class, device_connection, reusable_buffer, interface_number).map_err(|cause| CouldNotParseAlternateSettingAdditionalDescriptor { cause, interface_index, alternate_setting_index })?;
							return_ok_if_dead!(descriptors)
						},
						
						end_points:
						{
							let end_point_descriptors = Self::parse_end_point_descriptors(alternate_setting, interface_index, alternate_setting_index)?;
							let end_points = Self::parse_end_points(end_point_descriptors, interface_index, alternate_setting_index, interface_class, maximum_supported_usb_version, speed, device_connection)?;
							return_ok_if_dead!(end_points)
						},
					}
				)
			)
		)
	}
	
	#[inline(always)]
	fn parse_end_points(end_point_descriptors: &[libusb_endpoint_descriptor], interface_index: u8, alternate_setting_index: u8, interface_class: InterfaceClass, maximum_supported_usb_version: Version, speed: Option<Speed>, device_connection: &DeviceConnection) -> Result<DeadOrAlive<WrappedIndexMap<EndPointNumber, EndPoint>>, AlternateSettingParseError>
	{
		use AlternateSettingParseError::*;
		
		const MaximumNumberOfDirectionalEndPoints: usize = (InclusiveMaximumNumberOfEndPoints / 2) as usize;
		
		let number_of_end_points = end_point_descriptors.len();
		let mut end_points = WrappedIndexMap::with_capacity(min(number_of_end_points, MaximumNumberOfDirectionalEndPoints)).map_err(|cause| CouldNotAllocateMemoryForEndPoints { cause, interface_index, alternate_setting_index })?;
		
		for end_point_index in 0 .. (number_of_end_points as u8)
		{
			let end_point_descriptor = end_point_descriptors.get_unchecked_safe(end_point_index);
			return_ok_if_dead!(EndPoint::parse(end_point_descriptor, interface_class, maximum_supported_usb_version, device_connection, speed, &mut end_points).map_err(|cause| EndPointParse { cause, interface_index, alternate_setting_index, end_point_index })?);
		}
		
		if unlikely!(Speed::is_low_speed(speed))
		{
			let number_of_end_points = end_points.len();
			if unlikely!(number_of_end_points > 2)
			{
				return Err(LowSpeedDevicesCanNotHaveMoreThanTwoEndPoints { interface_index, alternate_setting_index, number_of_end_points })
			}
		}
		end_points.shrink_to_fit();
		
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
	fn parse_descriptors(alternate_setting: &libusb_interface_descriptor, interface_class: InterfaceClass, device_connection: &DeviceConnection, reusable_buffer: &mut ReusableBuffer, interface_number: InterfaceNumber) -> Result<DeadOrAlive<Vec<InterfaceExtraDescriptor>>, DescriptorParseError<InterfaceExtraDescriptorParseError>>
	{
		#[inline(always)]
		fn audio_control(device_connection: &DeviceConnection, extra: &[u8], protocol: AudioProtocol) -> Result<DeadOrAlive<Vec<InterfaceExtraDescriptor>>, DescriptorParseError<InterfaceExtraDescriptorParseError>>
		{
			InterfaceExtraDescriptorParser::parse_descriptors(device_connection, extra, AudioControlInterfaceExtraDescriptorParser(protocol))
		}
		
		#[inline(always)]
		fn audio_streaming(device_connection: &DeviceConnection, extra: &[u8], protocol: AudioProtocol) -> Result<DeadOrAlive<Vec<InterfaceExtraDescriptor>>, DescriptorParseError<InterfaceExtraDescriptorParseError>>
		{
			InterfaceExtraDescriptorParser::parse_descriptors(device_connection, extra, AudioStreamingInterfaceExtraDescriptorParser(protocol))
		}
		
		#[inline(always)]
		fn device_upgrade_firmware(device_connection: &DeviceConnection, extra: &[u8]) -> Result<DeadOrAlive<Vec<InterfaceExtraDescriptor>>, DescriptorParseError<InterfaceExtraDescriptorParseError>>
		{
			InterfaceExtraDescriptorParser::parse_descriptors(device_connection, extra, DeviceFirmwareUpgradeInterfaceAdditionalDescriptorParser)
		}
		
		#[inline(always)]
		fn human_interface_device(variant: HumanInterfaceDeviceVariant, device_connection: &DeviceConnection, reusable_buffer: &mut ReusableBuffer, extra: &[u8], interface_number: InterfaceNumber) -> Result<DeadOrAlive<Vec<InterfaceExtraDescriptor>>, DescriptorParseError<InterfaceExtraDescriptorParseError>>
		{
			InterfaceExtraDescriptorParser::parse_descriptors(device_connection, extra, HumanInterfaceDeviceInterfaceExtraDescriptorParser::new(reusable_buffer, interface_number, variant))
		}
		
		#[inline(always)]
		fn internet_printing_protocol(device_connection: &DeviceConnection, extra: &[u8]) -> Result<DeadOrAlive<Vec<InterfaceExtraDescriptor>>, DescriptorParseError<InterfaceExtraDescriptorParseError>>
		{
			InterfaceExtraDescriptorParser::parse_descriptors(device_connection, extra, InternetPrintingProtocolInterfaceExtraDescriptorParser)
		}
		
		#[inline(always)]
		fn video_control(device_connection: &DeviceConnection, extra: &[u8], protocol: VideoProtocol) -> Result<DeadOrAlive<Vec<InterfaceExtraDescriptor>>, DescriptorParseError<InterfaceExtraDescriptorParseError>>
		{
			InterfaceExtraDescriptorParser::parse_descriptors(device_connection, extra, VideoControlInterfaceExtraDescriptorParser(protocol))
		}
		
		#[inline(always)]
		fn smart_card(device_connection: &DeviceConnection, extra: &[u8], smart_card_protocol: SmartCardProtocol, bDescriptorType: u8) -> Result<DeadOrAlive<Vec<InterfaceExtraDescriptor>>, DescriptorParseError<InterfaceExtraDescriptorParseError>>
		{
			InterfaceExtraDescriptorParser::parse_descriptors(device_connection, extra, SmartCardInterfaceExtraDescriptorParser::new(smart_card_protocol, bDescriptorType))
		}
		
		#[inline(always)]
		fn unsupported_smart_card_with_descriptor_at_end_of_end_points(device_connection: &DeviceConnection, extra: &[u8]) -> Result<DeadOrAlive<Vec<InterfaceExtraDescriptor>>, DescriptorParseError<InterfaceExtraDescriptorParseError>>
		{
			unsupported(device_connection, extra)
		}
		
		#[inline(always)]
		fn unsupported(device_connection: &DeviceConnection, extra: &[u8]) -> Result<DeadOrAlive<Vec<InterfaceExtraDescriptor>>, DescriptorParseError<InterfaceExtraDescriptorParseError>>
		{
			InterfaceExtraDescriptorParser::parse_descriptors(device_connection, extra, UnsupportedInterfaceExtraDescriptorParser)
		}
		
		use HumanInterfaceDeviceVariant::*;
		
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
			Audio(AudioSubClass::Control(audio_protocol)) => audio_control(device_connection, extra, audio_protocol),
			Audio(AudioSubClass::Streaming(audio_protocol)) => audio_streaming(device_connection, extra, audio_protocol),
			
			ApplicationSpecific(DeviceFirmwareUpgrade(KnownOrUnrecognizedProtocol::Known)) => device_upgrade_firmware(device_connection, extra),
			
			HumanInterfaceDevice(HumanInterfaceDeviceInterfaceSubClass::None { unknown_protocol: None }) => human_interface_device(NotBoot, device_connection, reusable_buffer, extra, interface_number),
			HumanInterfaceDevice(Boot(HumanInterfaceDeviceInterfaceBootProtocol::None)) => human_interface_device(BootNone, device_connection, reusable_buffer, extra, interface_number),
			HumanInterfaceDevice(Boot(Keyboard)) => human_interface_device(BootKeyboard, device_connection, reusable_buffer, extra, interface_number),
			HumanInterfaceDevice(Boot(Mouse)) => human_interface_device(BootMouse, device_connection, reusable_buffer, extra, interface_number),
			
			Printer(PrinterSubClass::Known(PrinterProtocol::InternetPrintingProtocolOverUsb)) => internet_printing_protocol(device_connection, extra),
			
			Video(VideoSubClass::Control(video_protocol)) => video_control(device_connection, extra, video_protocol),
			
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
			SmartCard(SmartCardInterfaceSubClass::Known(BulkTransfer)) if extra.is_empty() => unsupported_smart_card_with_descriptor_at_end_of_end_points(device_connection, extra),
			
			SmartCard(SmartCardInterfaceSubClass::Known(BulkTransfer)) => smart_card(device_connection, extra, BulkTransfer, SmartCardDescriptorType),
			SmartCard(SmartCardInterfaceSubClass::Known(IccdVersionA)) => smart_card(device_connection, extra, IccdVersionA, SmartCardDescriptorType),
			SmartCard(SmartCardInterfaceSubClass::Known(IccdVersionB)) => smart_card(device_connection, extra, IccdVersionB, SmartCardDescriptorType),
			
			// Product Name (Vendor Identifier, Product Identifier, Year Added to CCID).
			// * USB Reader V2 (0x09C3, 0x0008, 2006).
			//
			// The bDescriptorType is 0x21.
			SmartCard(SmartCardInterfaceSubClass::Unrecognized(UnrecognizedSubClass { sub_class_code: 0x01, protocol_code: 0x01 })) if SmartCardInterfaceExtraDescriptor::extra_has_matching_length(extra) => smart_card(device_connection, extra, IccdVersionA, SmartCardDescriptorType),
			
			// These pre-standardization smart card devices have the following features:-
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
			VendorSpecific(UnrecognizedSubClass { sub_class_code: 0x5C, protocol_code: 0x00 }) if SmartCardInterfaceExtraDescriptor::extra_has_matching_length(extra) => smart_card(device_connection, extra, BulkTransfer, VendorSpecificDescriptorType),
			
			// This smart card case exists from before standardization; devices have the following features:-
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
			VendorSpecific(UnrecognizedSubClass { sub_class_code: 0x00, protocol_code: 0x00 }) if SmartCardInterfaceExtraDescriptor::extra_has_matching_length(extra) => smart_card(device_connection, extra, BulkTransfer, SmartCardDescriptorType),
			VendorSpecific(UnrecognizedSubClass { sub_class_code: 0x00, protocol_code: 0x01 }) if SmartCardInterfaceExtraDescriptor::extra_has_matching_length(extra) => smart_card(device_connection, extra, IccdVersionA, SmartCardDescriptorType),
			VendorSpecific(UnrecognizedSubClass { sub_class_code: 0x00, protocol_code: 0x02 }) if SmartCardInterfaceExtraDescriptor::extra_has_matching_length(extra) => smart_card(device_connection, extra, IccdVersionB, SmartCardDescriptorType),
			
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
			VendorSpecific(UnrecognizedSubClass { sub_class_code: 0x00, protocol_code: 0x00 }) if extra.is_empty() => unsupported_smart_card_with_descriptor_at_end_of_end_points(device_connection, extra),
			
			_ => unsupported(device_connection, extra),
		}
	}
}
