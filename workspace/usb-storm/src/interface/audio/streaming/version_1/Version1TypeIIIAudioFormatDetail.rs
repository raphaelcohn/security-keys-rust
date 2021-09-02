// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Type III audio format detail.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version1TypeIIIAudioFormatDetail
{
	format: Version1TypeIIIAudioFormat,
	
	number_of_channels: u8,
	
	sampling_frequency: SamplingFrequency,
}

impl Version1TypeIIIAudioFormatDetail
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn format(&self) -> Version1TypeIIIAudioFormat
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
	pub const fn subframe_size() -> SubframeSize
	{
		SubframeSize::Two
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn bit_resolution() -> u8
	{
		16
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn sampling_frequency(&self) -> &SamplingFrequency
	{
		&self.sampling_frequency
	}
	
	#[inline(always)]
	fn parse(format: Version1TypeIIIAudioFormat, bLength: u8, descriptor_body: &[u8]) -> Result<Version1AudioFormatDetail, FormatTypeIIIParseError>
	{
		use FormatTypeIIIParseError::*;
		
		const MinimumBLength: u8 = 8;
		if unlikely!(bLength < MinimumBLength)
		{
			return Err(BLengthIsLessThanMinimum)
		}
		
		let bSubframeSize = descriptor_body.u8(descriptor_index::<5>());
		if unlikely!(bSubframeSize != 2)
		{
			return Err(InvalidSubframeSize { bSubframeSize })
		}
		
		let bBitResolution = descriptor_body.u8(descriptor_index::<6>());
		if unlikely!(bBitResolution != 16)
		{
			return Err(InvalidBitResolution { bBitResolution })
		}
		
		Ok
		(
			Version1AudioFormatDetail::TypeIII
			(
				Self
				{
					format,
					
					number_of_channels: descriptor_body.u8(descriptor_index::<4>()),
					
					sampling_frequency: SamplingFrequency::parse::<MinimumBLength>(descriptor_body, bLength).map_err(SamplingFrequencyParse)?,
				}
			)
		)
	}
}
