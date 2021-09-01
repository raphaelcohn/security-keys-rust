// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Class-specific AS interface descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum AudioStreamingInterfaceExtraDescriptor
{
	/// See Device Class for Audio Release 1.0, 4.5.2 Class-Specific AS Interface Descriptor.
	Version_1_0(Version1AudioStreamingInterfaceExtraDescriptor),
	
	/// See Device Class for Audio Release 2.0, Section 4.9.2 Class-Specific AS Interface Descriptor.
	Version_2_0(Version2AudioStreamingInterfaceExtraDescriptor),
	
	/// See Device Class for Audio Release 3.0-Errata, Section 4.7.2 CLASS-SPECIFIC AS INTERFACE DESCRIPTOR.
	Version_3_0(Version3AudioStreamingInterfaceExtraDescriptor),
	
	/// Unrecognized.
	Unrecognised
	{
		#[allow(missing_docs)]
		protocol: u8,
		
		#[allow(missing_docs)]
		bLength: u8,
		
		#[allow(missing_docs)]
		remaining_bytes: Vec<u8>,
	}
}

impl AudioStreamingInterfaceExtraDescriptor
{
	#[inline(always)]
	fn parse_descriptor_version_1_0(bLength: u8, remaining_bytes: &[u8]) -> Result<DeadOrAlive<(Self, usize)>, AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		let (descriptor, consumed_length) = match Self::parse_descriptor_sub_type(bLength, remaining_bytes)?
		{
			Version1AudioStreamingInterfaceExtraDescriptor::AS_DESCRIPTOR_UNDEFINED => return Err(UndefinedInterfaceDescriptorSubType),
			
			Version1AudioStreamingInterfaceExtraDescriptor::AS_GENERAL => Version1AudioStreamingInterfaceExtraDescriptor::parse(bLength, remaining_bytes),
			
			descriptor_sub_type @ Version1AudioStreamingInterfaceExtraDescriptor::FORMAT_TYPE | descriptor_sub_type @ Version1AudioStreamingInterfaceExtraDescriptor::FORMAT_SPECIFIC => return Err(UnexpectedInterfaceDescriptorSubType { descriptor_sub_type }),
			
			descriptor_sub_type @ _ => return Err(UnrecognizedInterfaceDescriptorSubType { descriptor_sub_type })
		};
		Ok(Alive((AudioStreamingInterfaceExtraDescriptor::Version_1_0(descriptor), consumed_length)))
	}
	
	#[inline(always)]
	fn parse_descriptor_version_2_0(bLength: u8, remaining_bytes: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<(Self, usize)>, AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		const AS_DESCRIPTOR_UNDEFINED: u8 = 0x00;
		const AS_GENERAL: u8 = 0x01;
		const FORMAT_TYPE: u8 = 0x02;
		const ENCODER: u8 = 0x03;
		const DECODER: u8 = 0x04;
		
		let descriptor = match Self::parse_descriptor_sub_type(bLength, remaining_bytes)?
		{
			AS_DESCRIPTOR_UNDEFINED => return Err(UndefinedInterfaceDescriptorSubType),
			
			AS_GENERAL => (),
			
			FORMAT_TYPE => (),
			
			ENCODER => (),
			
			DECODER => (),
			
			descriptor_sub_type @ _ => return Err(UnrecognizedInterfaceDescriptorSubType { descriptor_sub_type })
		};
		Ok(Alive((AudioStreamingInterfaceExtraDescriptor::Version_2_0(descriptor), consumed_length)))
	}
	
	#[inline(always)]
	fn parse_descriptor_version_3_0(bLength: u8, remaining_bytes: &[u8]) -> Result<DeadOrAlive<(Self, usize)>, AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use AudioStreamingInterfaceExtraDescriptorParseError::*;
		use Version3AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		const AS_DESCRIPTOR_UNDEFINED: u8 = 0x00;
		const AS_GENERAL: u8 = 0x01;
		const AS_VALID_FREQ_RANGE: u8 = 0x02;
		
		let descriptor = match Self::parse_descriptor_sub_type(bLength, remaining_bytes)?
		{
			AS_DESCRIPTOR_UNDEFINED => return Err(UndefinedInterfaceDescriptorSubType),
			
			AS_GENERAL => Version3AudioStreamingInterfaceExtraDescriptor::parse_general(bLength, remaining_bytes)?,
			
			AS_VALID_FREQ_RANGE => Version3AudioStreamingInterfaceExtraDescriptor::parse_valid_sampling_frequency_range(bLength, remaining_bytes)?,
			
			descriptor_sub_type @ _ => return Err(UnrecognizedInterfaceDescriptorSubType { descriptor_sub_type })
		};
		Ok(Alive((AudioStreamingInterfaceExtraDescriptor::Version_3_0(descriptor), (bLength as usize) - DescriptorHeaderLength)))
	}
	
	#[inline(always)]
	fn parse_descriptor_version_unrecognized(bLength: u8, remaining_bytes: &[u8], protocol: u8) -> Result<DeadOrAlive<(Self, usize)>, AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		const MinimumBLength: u8 = MinimumStandardUsbDescriptorLength as u8;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<AudioStreamingInterfaceExtraDescriptorParseError, MinimumBLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		Ok
		(
			Alive
			(
				(
					AudioStreamingInterfaceExtraDescriptor::Unrecognised
					{
						protocol,
						
						bLength,
						
						remaining_bytes: Vec::new_from(descriptor_body).map_err(AudioStreamingInterfaceExtraDescriptorParseError::CouldNotAllocateMemoryForUnrecognized)?,
					},
					
					descriptor_body_length,
				)
			)
		)
	}
	
	#[inline(always)]
	fn parse_descriptor_sub_type(bLength: u8, remaining_bytes: &[u8]) -> Result<u8, AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		const SubDescriptorTypeLength: usize = 1;
		const MinimumBLength: u8 = (MinimumStandardUsbDescriptorLength + SubDescriptorTypeLength) as u8;
		if unlikely!(bLength < MinimumBLength)
		{
			return Err(BLengthTooShortToContainDescriptorSubType)
		}
		if unlikely!(remaining_bytes.is_empty())
		{
			return Err(TooShortToContainDescriptorSubType)
		}
		
		Ok(remaining_bytes.u8(2))
	}
	
	#[inline(always)]
	fn parse_descriptor_header<const MinimumBLength: u8>(bLength: u8, remaining_bytes: &[u8]) -> Result<(&[u8], usize), AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<AudioStreamingInterfaceExtraDescriptorParseError, MinimumBLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		
		Ok((descriptor_body, descriptor_body_length))
	}
}
