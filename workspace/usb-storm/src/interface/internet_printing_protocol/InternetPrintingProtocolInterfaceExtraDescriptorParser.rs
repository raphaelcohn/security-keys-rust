// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(super) struct InternetPrintingProtocolInterfaceExtraDescriptorParser;

impl DescriptorParser for InternetPrintingProtocolInterfaceExtraDescriptorParser
{
	type Descriptor = InternetPrintingProtocolInterfaceExtraDescriptor;
	
	type Error = InternetPrintingProtocolInterfaceExtraDescriptorParseError;
	
	#[inline(always)]
	fn parse_descriptor(&mut self, string_finder: &StringFinder, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<DeadOrAlive<(Self::Descriptor, usize)>>, Self::Error>
	{
		use InternetPrintingProtocolInterfaceExtraDescriptorParseError::*;
		
		match descriptor_type
		{
			0x21 => (),
			
			_ => return Err(DescriptorIsNeitherOfficialOrVendorSpecific(descriptor_type)),
		};
		
		const MinimumBLength: u8 = InternetPrintingProtocolInterfaceExtraDescriptorParser::MinimumBLength;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<InternetPrintingProtocolInterfaceExtraDescriptorParseError, MinimumBLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		let number_of_capability_descriptors =
		{
			let bNumDescriptors = descriptor_body.u8(descriptor_index::<3>());
			if unlikely!(bNumDescriptors == 0)
			{
				return Err(NoCapabilityDescriptors)
			}
			new_non_zero_u8(bNumDescriptors)
		};
		
		{
			let bCapabilitiesType = descriptor_body.u8(descriptor_index::<4>());
			if unlikely!(bCapabilitiesType != 0x00)
			{
				return Err(UnrecognizedCapabilitiesType { bCapabilitiesType })
			}
		}
		{
			let bCapabilitiesLength = descriptor_body.u8(descriptor_index::<5>());
			if unlikely!(bCapabilitiesLength != 0x04)
			{
				return Err(UnrecognizedCapabilitiesLength { bCapabilitiesLength })
			}
		}
		
		let wBasicCapabilities = descriptor_body.u16(descriptor_index::<6>());
		
		Ok
		(
			Some
			(
				Alive
				(
					(
						InternetPrintingProtocolInterfaceExtraDescriptor
						{
							print_class_specification_release_major_version: descriptor_body.u8(descriptor_index::<2>()),
							
							basic_capabilities: WrappedBitFlags::from_bits_unchecked((wBasicCapabilities & 0b1_1111) as u8),
						
							authentication:
							{
								use Authentication::*;
								match (wBasicCapabilities >> 5) & 0b11
								{
									0b00 => NoAuthentication,
									
									0b01 => UsernamePassword,
									
									0b10 => return Err(ReservedAuthenticationInBasicCapabilities),
									
									0b11 => Negotiate,
									
									_ => unreachable!(),
								}
							},
							
							versions_supported: match string_finder.find_string(descriptor_body.u8(descriptor_index::<8>())).map_err(InvalidVersionsSupportedString)?
							{
								Alive(value) => value,
								
								Dead => return Ok(Some(Dead))
							},
							
							printer_uuid: match string_finder.find_string(descriptor_body.u8(descriptor_index::<9>())).map_err(InvalidPrinterUuidString)?
							{
								Alive(value) => value,
								
								Dead => return Ok(Some(Dead))
							},
						
							vendor_capability_descriptors: Self::parse_vendor_capability_descriptors(number_of_capability_descriptors, descriptor_body)?,
						},
						
						descriptor_body_length,
					)
				)
			)
		)
	}
}

impl InternetPrintingProtocolInterfaceExtraDescriptorParser
{
	const MinimumBLength: u8 = 10;
	
	#[inline(always)]
	fn parse_vendor_capability_descriptors(number_of_capability_descriptors: NonZeroU8, descriptor_body: &[u8]) -> Result<Vec<VendorCapabilityDescriptor>, InternetPrintingProtocolInterfaceExtraDescriptorParseError>
	{
		use InternetPrintingProtocolInterfaceExtraDescriptorParseError::*;
		
		let number_of_vendor_capability_descriptors = number_of_capability_descriptors.get() - 1;
		let mut vendor_capability_descriptors_bytes = descriptor_body.get_unchecked_range_safe(((InternetPrintingProtocolInterfaceExtraDescriptorParser::MinimumBLength as usize) - DescriptorHeaderLength) .. );
		
		Vec::new_populated(number_of_vendor_capability_descriptors as usize, VendorCapabilityDescriptorsCanNotBeAllocated, |index|
		{
			const HeaderLength: usize = 2;
			
			let length = vendor_capability_descriptors_bytes.len();
			if unlikely!(length < HeaderLength)
			{
				return Err(VendorCapabilityDescriptorHeaderTooShort { index, length })
			}
			
			let descriptor_type = vendor_capability_descriptors_bytes.u8(0);
			if unlikely!(descriptor_type < 0x20)
			{
				return Err(VendorCapabilityDescriptorDoesNotUseVendorSpecificDescriptorType { index, descriptor_type })
			}
			
			let descriptor_length = vendor_capability_descriptors_bytes.u8(1) as usize;
			let required_length = HeaderLength + descriptor_length;
			if unlikely!(length < required_length)
			{
				return Err(VendorCapabilityDescriptorLengthTooShort { index, length, required_length })
			}
			
			let bytes_slice = vendor_capability_descriptors_bytes.bytes(2, descriptor_length as usize);
			let bytes = Vec::new_from(bytes_slice).map_err(|cause| VendorCapabilityDescriptorBytesCanNotBeAllocated { cause, index })?;
			
			vendor_capability_descriptors_bytes = vendor_capability_descriptors_bytes.get_unchecked_range_safe(required_length .. );
			
			Ok
			(
				VendorCapabilityDescriptor
				{
					descriptor_type,
				
					bytes,
				}
			)
		})
	}
}
