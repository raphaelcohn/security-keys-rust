// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Type I audio format detail.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version1TypeIAudioFormatDetail
{
	format: Version1TypeIAudioFormat,

	number_of_channels: u8,
	
	subframe_size: SubframeSize,

	bit_resolution: u8,
	
	sampling_frequency: SamplingFrequency,
}

impl Version1TypeIAudioFormatDetail
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn format(&self) -> Version1TypeIAudioFormat
	{
		self.format
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn number_of_channels(&self) -> u8
	{
		self.number_of_channels
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn subframe_size(&self) -> SubframeSize
	{
		self.subframe_size
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn bit_resolution(&self) -> u8
	{
		self.bit_resolution
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn sampling_frequency(&self) -> &SamplingFrequency
	{
		&self.sampling_frequency
	}
	
	#[inline(always)]
	fn parse(format: Version1TypeIAudioFormat, bLength: u8, remaining_bytes: &[u8]) -> Result<(Version1AudioFormatDetail, usize), Version1AudioStreamingInterfaceExtraDescriptorParseError>
	{
		use Version1AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		const MinimumBLength: u8 = 8;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<Version1AudioStreamingInterfaceExtraDescriptorParseError, MinimumBLength>(remaining_bytes, bLength, FormatTypeIBLengthIsLessThanMinimum, FormatTypeIBLengthExceedsRemainingBytes)?;
		
		Ok
		(
			(
				Version1AudioFormatDetail::TypeI
				(
					Self
					{
						format,
						
						number_of_channels: descriptor_body.u8(descriptor_index::<4>()),
					
						subframe_size:
						{
							let bSubframeSize = descriptor_body.u8(descriptor_index::<5>());
							match bSubframeSize
							{
								0 => return Err(InvalidTypeISubframeSize { bSubframeSize }),
								
								1 ..= 4 => unsafe { transmute(bSubframeSize) },
								
								_ => return Err(InvalidTypeISubframeSize { bSubframeSize })
							}
						},
					
						bit_resolution: descriptor_body.u8(descriptor_index::<6>()),
						
						sampling_frequency: SamplingFrequency::parse(MinimumBLength, descriptor_body, bLength)?,
					}
				),
				
				descriptor_body_length,
			)
		)
	}
}
