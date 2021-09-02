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
	fn parse_descriptor_version_1_0(bLength: u8, descriptor_body_followed_by_remaining_bytes: &[u8]) -> Result<DeadOrAlive<(Self, usize)>, Version1AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use GenericAudioStreamingInterfaceExtraDescriptorParseError::*;
		use Version1AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		let (descriptor, consumed_length) = match Self::parse_descriptor_sub_type(bLength, descriptor_body_followed_by_remaining_bytes, BLengthTooShortToContainDescriptorSubType, TooShortToContainDescriptorSubType)?
		{
			Version1AudioStreamingInterfaceExtraDescriptor::AS_DESCRIPTOR_UNDEFINED => Err(UndefinedInterfaceDescriptorSubType)?,
			
			Version1AudioStreamingInterfaceExtraDescriptor::AS_GENERAL => Version1AudioStreamingInterfaceExtraDescriptor::parse(bLength, descriptor_body_followed_by_remaining_bytes)?,
			
			Version1AudioStreamingInterfaceExtraDescriptor::FORMAT_TYPE => Err(FormatTypeIsUnexpected)?,
			
			Version1AudioStreamingInterfaceExtraDescriptor::FORMAT_SPECIFIC => Err(FormatSpecificIsUnexpected)?,
			
			descriptor_sub_type @ _ => Err(UnrecognizedInterfaceDescriptorSubType { descriptor_sub_type })?,
		};
		Ok(Alive((AudioStreamingInterfaceExtraDescriptor::Version_1_0(descriptor), consumed_length)))
	}
	
	#[inline(always)]
	fn parse_descriptor_version_2_0(bLength: u8, descriptor_body_followed_by_remaining_bytes: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<(Self, usize)>, Version2AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use GenericAudioStreamingInterfaceExtraDescriptorParseError::*;
		
		let dead_or_alive = match Self::parse_descriptor_sub_type(bLength, descriptor_body_followed_by_remaining_bytes, BLengthTooShortToContainDescriptorSubType, TooShortToContainDescriptorSubType)?
		{
			Version2AudioStreamingInterfaceExtraDescriptor::AS_DESCRIPTOR_UNDEFINED => Err(UndefinedInterfaceDescriptorSubType)?,
			
			Version2AudioStreamingInterfaceExtraDescriptor::AS_GENERAL => Version2AudioStreamingInterfaceExtraDescriptor::parse_general(bLength, descriptor_body_followed_by_remaining_bytes, string_finder)?,
			
			Version2AudioStreamingInterfaceExtraDescriptor::FORMAT_TYPE => Err(Version2AudioStreamingInterfaceExtraDescriptorParseError::FormatTypeIsUnexpected)?,
			
			Version2AudioStreamingInterfaceExtraDescriptor::ENCODER => Version2AudioStreamingInterfaceExtraDescriptor::parse_encoder(bLength, descriptor_body_followed_by_remaining_bytes, string_finder)?,
			
			Version2AudioStreamingInterfaceExtraDescriptor::DECODER => Version2AudioStreamingInterfaceExtraDescriptor::parse_decoder(bLength, descriptor_body_followed_by_remaining_bytes, string_finder)?,
			
			descriptor_sub_type @ _ => Err(UnrecognizedInterfaceDescriptorSubType { descriptor_sub_type })?,
		};
		let (descriptor, consumed_length) = return_ok_if_dead!(dead_or_alive);
		Ok(Alive((AudioStreamingInterfaceExtraDescriptor::Version_2_0(descriptor), consumed_length)))
	}
	
	#[inline(always)]
	fn parse_descriptor_version_3_0(bLength: u8, descriptor_body_followed_by_remaining_bytes: &[u8]) -> Result<DeadOrAlive<(Self, usize)>, Version3AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use GenericAudioStreamingInterfaceExtraDescriptorParseError::*;
		
		let descriptor = match Self::parse_descriptor_sub_type(bLength, descriptor_body_followed_by_remaining_bytes, BLengthTooShortToContainDescriptorSubType, TooShortToContainDescriptorSubType)?
		{
			Version3AudioStreamingInterfaceExtraDescriptor::AS_DESCRIPTOR_UNDEFINED => Err(UndefinedInterfaceDescriptorSubType)?,
			
			Version3AudioStreamingInterfaceExtraDescriptor::AS_GENERAL => Version3AudioStreamingInterfaceExtraDescriptor::parse_general(bLength, descriptor_body_followed_by_remaining_bytes)?,
			
			Version3AudioStreamingInterfaceExtraDescriptor::AS_VALID_FREQ_RANGE => Version3AudioStreamingInterfaceExtraDescriptor::parse_valid_sampling_frequency_range(bLength, descriptor_body_followed_by_remaining_bytes)?,
			
			descriptor_sub_type @ _ => Err(UnrecognizedInterfaceDescriptorSubType { descriptor_sub_type })?
		};
		Ok(Alive((AudioStreamingInterfaceExtraDescriptor::Version_3_0(descriptor), (bLength as usize) - DescriptorHeaderLength)))
	}
	
	#[inline(always)]
	fn parse_descriptor_version_unrecognized(bLength: u8, descriptor_body_followed_by_remaining_bytes: &[u8], protocol: u8) -> Result<DeadOrAlive<(Self, usize)>, UnrecognizedAudioStreamingInterfaceExtraDescriptorParseError>
	{
		use UnrecognizedAudioStreamingInterfaceExtraDescriptorParseError::*;
		
		const MinimumBLength: u8 = MinimumStandardUsbDescriptorLength as u8;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<_, MinimumBLength>(descriptor_body_followed_by_remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		Ok
		(
			Alive
			(
				(
					AudioStreamingInterfaceExtraDescriptor::Unrecognised
					{
						protocol,
						
						bLength,
						
						remaining_bytes: Vec::new_from(descriptor_body).map_err(CouldNotAllocateMemoryForUnrecognized)?,
					},
					
					descriptor_body_length,
				)
			)
		)
	}
	
	#[inline(always)]
	fn parse_descriptor_sub_type<E: error::Error>(bLength: u8, descriptor_body_followed_by_remaining_bytes: &[u8], b_length_too_short_error: E, too_short_error: E) -> Result<u8, E>
	{
		const SubDescriptorTypeLength: usize = 1;
		const MinimumBLength: u8 = (MinimumStandardUsbDescriptorLength + SubDescriptorTypeLength) as u8;
		if unlikely!(bLength < MinimumBLength)
		{
			return Err(b_length_too_short_error)
		}
		if unlikely!(descriptor_body_followed_by_remaining_bytes.is_empty())
		{
			return Err(too_short_error)
		}
		
		Ok(descriptor_body_followed_by_remaining_bytes.u8(descriptor_index::<2>()))
	}
}
