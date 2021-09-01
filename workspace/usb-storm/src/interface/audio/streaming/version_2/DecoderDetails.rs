// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Decoder details.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum DecoderDetails
{
	#[allow(missing_docs)]
	Undefined
	{
		data: Vec<u8>,
	},
	
	#[allow(missing_docs)]
	Other
	{
		data: Vec<u8>,
	},
	
	#[allow(missing_docs)]
	MPEG
	{
		common: MpegCommon,
		
		support_for_half_fs: bool,
		
		controls: DecoderControls,
		
		description: Option<LocalizedStrings>,
	},
	
	#[allow(missing_docs)]
	AC_3
	{
		common: Ac3Common,
		
		controls: DecoderControls,
		
		description: Option<LocalizedStrings>,
	},
	
	#[allow(missing_docs)]
	WMA
	{
		profiles: WrappedBitFlags<WmaProfile>,
		
		supports_lossless_decoding: bool,
		
		controls: DecoderControls,
		
		description: Option<LocalizedStrings>,
	},
	
	#[allow(missing_docs)]
	DTS
	{
		capabilities: WrappedBitFlags<DtsCapability>,
		
		controls: DecoderControls,
		
		description: Option<LocalizedStrings>,
	},

	#[allow(missing_docs)]
	Unrecognized
	{
		data: Vec<u8>,
		
		decoder_type: u8,
	}
}

impl DecoderDetails
{
	#[inline(always)]
	fn parse(bLength: u8, remaining_bytes: &[u8], decoder_type: u8, string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, DecoderParseError>
	{
		use DecoderDetails::*;
		
		let decoder = match decoder_type
		{
			0x00 => Alive
			(
				Undefined
				{
					data: Self::parse_data(bLength, remaining_bytes)?,
				}
			),
			
			0x01 => Alive
			(
				Other
				{
					data: Self::parse_data(bLength, remaining_bytes)?,
				}
			),
			
			0x02 => Self::parse_mpeg(bLength, remaining_bytes, string_finder)?,
			
			0x03 => Self::parse_ac_3(bLength, remaining_bytes, string_finder)?,
			
			0x04 => Self::parse_wma(bLength, remaining_bytes, string_finder)?,
			
			0x05 => Self::parse_dts(bLength, remaining_bytes, string_finder)?,
			
			_ => Alive
			(
				Unrecognized
				{
					data: Self::parse_data(bLength, remaining_bytes)?,
				
					decoder_type,
				}
			),
		};
		Ok(decoder)
	}
	
	#[inline(always)]
	fn parse_data(bLength: u8, remaining_bytes: &[u8]) -> Result<Vec<u8>, DecoderParseError>
	{
		let data = remaining_bytes.get_unchecked_range_safe(5 .. (bLength as usize));
		Vec::new_from(data).map_err(DecoderParseError::CouldNotAllocateMemoryForUndefinedOrOtherOrUnrecognizedData)
	}
	
	#[inline(always)]
	fn parse_mpeg(bLength: u8, remaining_bytes: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, MpegEncoderParseError>
	{
		use MpegEncoderParseError::*;
		
		const BLength: u8 = 10;
		let (descriptor_body, _descriptor_body_length) = verify_remaining_bytes::<MpegEncoderParseError, BLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		let bmMPEGCapabilities = remaining_bytes.u16(5);
		Ok
		(
			Alive
			(
				DecoderDetails::MPEG
				{
					common:
					{
						let bmMPEGFeatures = remaining_bytes.u8(7);
						MpegCommon::parse(bmMPEGCapabilities, bmMPEGFeatures, ReservedMpeg2MultilingualSupport)?
					},
					
					support_for_half_fs: (bmMPEGCapabilities & 0b0100_0000_0000) != 0,
					
					controls: DecoderControls::parse::<8, 0>(descriptor_body)?,
					
					description: return_ok_if_dead!(Self::parse_description::<MpegEncoderParseError, _, 9>(descriptor_body, string_finder, InvalidDescriptionString)?)
				}
			)
		)
	}
	
	#[inline(always)]
	fn parse_ac_3(bLength: u8, remaining_bytes: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, Ac3EncoderParseError>
	{
		use Ac3EncoderParseError::*;
		
		const BLength: u8 = 12;
		let (descriptor_body, _descriptor_body_length) = verify_remaining_bytes::<Ac3EncoderParseError, BLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		Ok
		(
			Alive
			(
				DecoderDetails::AC_3
				{
					common: Ac3Common::parse(remaining_bytes, Ac3MustSupportBitStreamIdModes0To9Inclusive)?,
					
					controls: DecoderControls::parse::<10, 0>(descriptor_body)?,
					
					description: return_ok_if_dead!(Self::parse_description::<Ac3EncoderParseError, _, 11>(descriptor_body, string_finder, InvalidDescriptionString)?)
				}
			)
		)
	}
	
	#[inline(always)]
	fn parse_wma(bLength: u8, remaining_bytes: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, WmaEncoderParseError>
	{
		use WmaEncoderParseError::*;
		
		const BLength: u8 = 9;
		let (descriptor_body, _descriptor_body_length) = verify_remaining_bytes::<WmaEncoderParseError, BLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		let bmWMAProfile = descriptor_body.u16(descriptor_index::<5>());
		Ok
		(
			Alive
			(
				DecoderDetails::WMA
				{
					profiles: WrappedBitFlags::from_bits_truncate(bmWMAProfile),
					
					supports_lossless_decoding: (bmWMAProfile & 0b100_0000_0000) != 0,
					
					controls: DecoderControls::parse::<7, 0>(descriptor_body)?,
					
					description: return_ok_if_dead!(Self::parse_description::<WmaEncoderParseError, _, 8>(descriptor_body, string_finder, InvalidDescriptionString)?)
				}
			)
		)
	}
	
	#[inline(always)]
	fn parse_dts(bLength: u8, remaining_bytes: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<Self>, DtsEncoderParseError>
	{
		use DtsEncoderParseError::*;
		
		const BLength: u8 = 8;
		let (descriptor_body, _descriptor_body_length) = verify_remaining_bytes::<DtsEncoderParseError, BLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		Ok
		(
			Alive
			(
				DecoderDetails::DTS
				{
					capabilities: WrappedBitFlags::from_bits_truncate(descriptor_body.u8(descriptor_index::<5>())),
					
					controls: DecoderControls::parse::<6, 1>(descriptor_body)?,
					
					description: return_ok_if_dead!(Self::parse_description::<DtsEncoderParseError, _, 7>(descriptor_body, string_finder, InvalidDescriptionString)?)
				}
			)
		)
	}
	
	#[inline(always)]
	fn parse_description<E: error::Error, Error: FnOnce(GetLocalizedStringError) -> E, const Index: usize>(descriptor_body: &[u8], string_finder: &StringFinder, error: Error) -> Result<DeadOrAlive<Option<LocalizedStrings>>, E>
	{
		string_finder.find_string(descriptor_body.u8(descriptor_index::<Index>())).map_err(error)
	}
}
