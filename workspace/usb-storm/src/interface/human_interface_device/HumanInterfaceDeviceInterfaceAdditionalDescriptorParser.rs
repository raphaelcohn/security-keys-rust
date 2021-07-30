// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(super) struct HumanInterfaceDeviceInterfaceAdditionalDescriptorParser(HumanInterfaceDeviceInterfaceAdditionalVariant);

impl AdditionalDescriptorParser for HumanInterfaceDeviceInterfaceAdditionalDescriptorParser
{
	type Descriptor = HumanInterfaceDeviceInterfaceAdditionalDescriptor;
	
	type Error = HumanInterfaceDeviceInterfaceAdditionalDescriptorParseError;
	
	#[inline(always)]
	fn no_descriptors_valid() -> bool
	{
		false
	}
	
	#[inline(always)]
	fn multiple_descriptors_valid() -> bool
	{
		false
	}
	
	#[inline(always)]
	fn parse_descriptor(&mut self, descriptor_type: DescriptorType, bytes: &[u8]) -> Result<Option<Self::Descriptor>, Self::Error>
	{
		use HumanInterfaceDeviceInterfaceAdditionalDescriptorParseError::*;
		
		match descriptor_type
		{
			0x21 => (),
			
			_ => return Err(DescriptorIsNeitherOfficialOrVendorSpecific(descriptor_type)),
		};
		
		const AdjustedMinimumLength: usize = 9 - LengthAdjustment;
		if unlikely!(bytes.len() < AdjustedMinimumLength)
		{
			return Err(WrongLength)
		}
		
		let number_of_class_descriptors_including_mandatory_report =
		{
			let bNumClassDescriptors = bytes.u8::<5>();
			if unlikely!(bNumClassDescriptors == 0)
			{
				return Err(ZeroNumberOfClassDescriptors)
			}
			new_non_zero_u8(bNumClassDescriptors)
		};
		
		{
			let report_descriptor_type = bytes.u8::<6>(); //
			if unlikely!(report_descriptor_type != 0x22)
			{
				return Err(UnrecognisedReportDescriptorType(report_descriptor_type))
			}
		}
		
		Ok
		(
			Some
			(
				HumanInterfaceDeviceInterfaceAdditionalDescriptor
				{
					variant: self.0,
					
					version: bytes.version::<2>().map_err(Version)?,
					
					country_code: match bytes.u8::<4>()
					{
						0 => None,
						
						country_code @ 1 ..= 35 => Some(unsafe { transmute(country_code) }),
						
						reserved => return Err(ReservedCountryCode(reserved))
					}
					,
					report_descriptor_length: bytes.u16::<7>(),
				
					optional_descriptors: Self::parse_optional_descriptors(number_of_class_descriptors_including_mandatory_report, bytes.get_unchecked_range_safe(AdjustedMinimumLength .. ))?,
				}
			)
		)
	}
}

impl HumanInterfaceDeviceInterfaceAdditionalDescriptorParser
{
	#[inline(always)]
	pub(super) const fn new(variant: HumanInterfaceDeviceInterfaceAdditionalVariant) -> Self
	{
		Self(variant)
	}
	
	#[inline(always)]
	fn parse_optional_descriptors(number_of_class_descriptors_including_mandatory_report: NonZeroU8, optional_descriptors_bytes: &[u8]) -> Result<Vec<HumanInterfaceDeviceOptionalDescriptor>, HumanInterfaceDeviceInterfaceAdditionalDescriptorParseError>
	{
		use HumanInterfaceDeviceInterfaceAdditionalDescriptorParseError::*;
		
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
		
		let mut optional_descriptors = Vec::new_with_capacity(number_of_optional_descriptors).map_err(CouldNotAllocateSpaceForOptionalDescriptors)?;
		
		let mut byte_index = 0;
		for _ in 0 ..number_of_optional_descriptors
		{
			use HumanInterfaceDeviceOptionalDescriptorType::*;
			optional_descriptors.push
			(
				HumanInterfaceDeviceOptionalDescriptor
				{
					descriptor_type: match optional_descriptors_bytes.u8_unadjusted(byte_index)
					{
						0x23 => Physical,
						
						reserved @ 0x24 ..= 0x2F => Reserved(reserved),
						
						bDescriptorType @ _ => return Err(InvalidOptionalDescriptor { bDescriptorType })
					},
					
					length: optional_descriptors_bytes.u16_unadjusted(byte_index + OptionalDescriptorTypeSize),
				}
			);
			
			byte_index = byte_index + OptionalDescriptorSize
		}
		
		Ok(optional_descriptors)
	}
}
