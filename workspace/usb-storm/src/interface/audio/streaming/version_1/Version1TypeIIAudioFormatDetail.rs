// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Type II audio format detail.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version1TypeIIAudioFormatDetail
{
	maximum_bit_rate_in_kilobits_per_second: u16,

	maximum_samples_per_frame: u16,
	
	sampling_frequency: SamplingFrequency,
	
	specific: Version1TypeIIAudioFormatDetailSpecific,
}

impl Version1TypeIIAudioFormatDetail
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_bit_rate_in_kilobits_per_second(&self) -> u16
	{
		self.maximum_bit_rate_in_kilobits_per_second
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_samples_per_frame(&self) -> u16
	{
		self.maximum_samples_per_frame
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn sampling_frequency(&self) -> SamplingFrequency
	{
		self.sampling_frequency
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn specific(&self) -> &Version1TypeIIAudioFormatDetailSpecific
	{
		&self.specific
	}
	
	#[inline(always)]
	fn parse(format: Version1TypeIIAudioFormat, bLength: u8, remaining_bytes: &[u8]) -> Result<(Version1AudioFormatDetail, usize), Version1AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use Version1AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		const MinimumBLength: u8 = 9;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<Version1AudioStreamingInterfaceExtraDescriptorParseError, MinimumBLength>(remaining_bytes, bLength, FormatTypeIIBLengthIsLessThanMinimum, FormatTypeIIBLengthExceedsRemainingBytes)?;
		
		let (specific, b_length) = Version1TypeIIAudioFormatDetailSpecific::parse(format, remaining_bytes.get_unchecked_range_safe(descriptor_body_length .. ))?;
		
		Ok
		(
			(
				Version1AudioFormatDetail::TypeII
				(
					Self
					{
						maximum_bit_rate_in_kilobits_per_second: descriptor_body.u16(descriptor_index::<4>()),
						
						maximum_samples_per_frame: descriptor_body.u16(descriptor_index::<6>()),
						
						sampling_frequency: SamplingFrequency::parse(MinimumBLength as usize, descriptor_body)?,
					
						specific,
					}
				),
				
				descriptor_body_length + b_length,
			)
		)
	}
}
