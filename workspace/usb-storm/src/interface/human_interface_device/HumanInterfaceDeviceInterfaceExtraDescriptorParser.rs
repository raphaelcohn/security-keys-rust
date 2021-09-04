// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug)]
pub(super) struct HumanInterfaceDeviceInterfaceExtraDescriptorParser<'a>
{
	reusable_buffer: &'a mut ReusableBuffer,
	
	interface_number: InterfaceNumber,
	
	variant: HumanInterfaceDeviceVariant,
}

impl<'a> DescriptorParser for HumanInterfaceDeviceInterfaceExtraDescriptorParser<'a>
{
	type Descriptor = HumanInterfaceDeviceInterfaceExtraDescriptor;
	
	type Error = HumanInterfaceDeviceInterfaceExtraDescriptorParseError;
	
	#[inline(always)]
	fn parse_descriptor(&mut self, device_connection: &DeviceConnection, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<DeadOrAlive<(Self::Descriptor, usize)>>, Self::Error>
	{
		use HumanInterfaceDeviceInterfaceExtraDescriptorParseError::*;
		
		match descriptor_type
		{
			0x21 => (),
			
			_ => return Err(DescriptorIsNeitherOfficialOrVendorSpecific(descriptor_type)),
		};
		
		const MinimumBLength: u8 = HumanInterfaceDeviceInterfaceExtraDescriptorParser::MinimumBLength;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<_, MinimumBLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		let number_of_class_descriptors_including_mandatory_report =
		{
			let bNumClassDescriptors = descriptor_body.u8(descriptor_index::<5>());
			if unlikely!(bNumClassDescriptors == 0)
			{
				return Err(ZeroNumberOfClassDescriptors)
			}
			new_non_zero_u8(bNumClassDescriptors)
		};
		
		{
			let report_descriptor_type = descriptor_body.u8(descriptor_index::<6>());
			if unlikely!(report_descriptor_type != 0x22)
			{
				return Err(UnrecognisedReportDescriptorType(report_descriptor_type))
			}
		}
		
		Ok
		(
			Some
			(
				Alive
				(
					(
						HumanInterfaceDeviceInterfaceExtraDescriptor
						{
							variant: self.variant,
							
							version: Self::parse_version(descriptor_body)?,
							
							country_code: Self::parse_country_code(descriptor_body)?,
							
							report: match self.parse_report(descriptor_body, device_connection)?
							{
								Dead => return Ok(Some(Dead)),
								
								Alive(report) => report,
							},
						
							optional_descriptors: Self::parse_optional_descriptors(number_of_class_descriptors_including_mandatory_report, descriptor_body)?,
						},
						descriptor_body_length,
					)
				)
			)
		)
	}
}

impl<'a> HumanInterfaceDeviceInterfaceExtraDescriptorParser<'a>
{
	const MinimumBLength: u8 = 9;
	
	#[inline(always)]
	pub(super) fn new(reusable_buffer: &'a mut ReusableBuffer, interface_number: InterfaceNumber, variant: HumanInterfaceDeviceVariant) -> Self
	{
		Self
		{
			reusable_buffer,
			
			interface_number,
			
			variant,
		}
	}
	
	#[inline(always)]
	fn parse_version(descriptor_body: &[u8]) -> Result<Version, HumanInterfaceDeviceInterfaceExtraDescriptorParseError>
	{
		descriptor_body.version(descriptor_index::<2>()).map_err(HumanInterfaceDeviceInterfaceExtraDescriptorParseError::Version)
	}
	
	#[inline(always)]
	fn parse_country_code(descriptor_body: &[u8]) -> Result<Option<HumanInterfaceDeviceCountryCode>, HumanInterfaceDeviceInterfaceExtraDescriptorParseError>
	{
		match descriptor_body.u8(descriptor_index::<4>())
		{
			0 => Ok(None),
			
			country_code @ 1 ..= 35 => Ok(Some(unsafe { transmute(country_code) })),
			
			reserved => Err(HumanInterfaceDeviceInterfaceExtraDescriptorParseError::ReservedCountryCode(reserved))
		}
	}
	
	#[inline(always)]
	fn parse_report(&mut self, descriptor_body: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<CollectionCommon>, ReportParseError>
	{
		let report_total_length = descriptor_body.u16(descriptor_index::<7>());
		let report_parser = ReportParser::new(device_connection)?;
		report_parser.get_and_parse(self.reusable_buffer, self.interface_number, report_total_length)
	}
	
	#[inline(always)]
	fn parse_optional_descriptors(number_of_class_descriptors_including_mandatory_report: NonZeroU8, descriptor_body: &[u8]) -> Result<Vec<HumanInterfaceDeviceOptionalDescriptor>, OptionalDescriptorParseError>
	{
		use OptionalDescriptorParseError::*;
		
		let optional_descriptors_bytes = descriptor_body.get_unchecked_range_safe(((Self::MinimumBLength as usize) - DescriptorHeaderLength) .. );
		
		let number_of_optional_descriptors = (number_of_class_descriptors_including_mandatory_report.get() - 1) as usize;
		
		let optional_descriptors_bytes_length = optional_descriptors_bytes.len();
		
		const OptionalDescriptorTypeSize: usize = 1;
		const OptionalDescriptorLength: usize = 2;
		const OptionalDescriptorSize: usize = OptionalDescriptorTypeSize + OptionalDescriptorLength;
		
		if unlikely!(optional_descriptors_bytes_length / OptionalDescriptorSize != number_of_optional_descriptors)
		{
			return Err(IncorrectNumberOfOptionalDescriptors)
		}
		
		if unlikely!(optional_descriptors_bytes_length % OptionalDescriptorSize != 0)
		{
			return Err(ExcessBytesAfterOptionalDescriptors)
		}
		
		let mut byte_index = 0;
		let optional_descriptors = Vec::new_populated(number_of_optional_descriptors, CouldNotAllocateSpaceForOptionalDescriptors, |_|
		{
			use HumanInterfaceDeviceOptionalDescriptorType::*;
			let descriptor = HumanInterfaceDeviceOptionalDescriptor
			{
				descriptor_type: match optional_descriptors_bytes.u8(byte_index)
				{
					0x23 => Physical,
					
					reserved @ 0x24 ..= 0x2F => Reserved(reserved),
					
					bDescriptorType @ _ => return Err(InvalidOptionalDescriptor { bDescriptorType })
				},
				
				length: optional_descriptors_bytes.u16(byte_index + OptionalDescriptorTypeSize),
			};
			
			byte_index = byte_index + OptionalDescriptorSize;
			Ok(descriptor)
		})?;
		
		Ok(optional_descriptors)
	}
}
