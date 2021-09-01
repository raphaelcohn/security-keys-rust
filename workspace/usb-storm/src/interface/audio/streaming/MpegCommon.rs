// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// MPEG common information.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MpegCommon
{
	internal_dynamic_range_control: InternalDynamicRangeControl,
	
	layer_support: WrappedBitFlags<MpegLayer>,
	
	mpeg_1_only: bool,
	
	mpeg_1_dual_channel: bool,
	
	mpeg_2_second_stereo: bool,
	
	mpeg_2_seven_dot_one_channel_augmentation: bool,
	
	adaptive_multi_channel_prediction: bool,
	
	mpeg_2_multilingual_support: Mpeg2MultilingualSupport,
}

impl MpegCommon
{
	#[inline(always)]
	fn parse<E: error::Error>(bmMPEGCapabilities: u16, bmMPEGFeatures: u8, reserved_multilingual_support_error: E) -> Result<Self, E>
	{
		Ok
			(
				Self
				{
					internal_dynamic_range_control:
					{
						InternalDynamicRangeControl::from_2_bits((bmMPEGFeatures >> 4) as u8)
					},
					
					layer_support: WrappedBitFlags::from_bits_truncate(bmMPEGCapabilities as u8),
					
					mpeg_1_only: (bmMPEGCapabilities & 0b1000) != 0,
					
					mpeg_1_dual_channel: (bmMPEGCapabilities & 0b0001_0000) != 0,
					
					mpeg_2_second_stereo: (bmMPEGCapabilities & 0b0010_0000) != 0,
					
					mpeg_2_seven_dot_one_channel_augmentation: (bmMPEGCapabilities & 0b0100_0000) != 0,
					
					adaptive_multi_channel_prediction: (bmMPEGCapabilities & 0b1000_0000) != 0,
					
					mpeg_2_multilingual_support:
					{
						use Mpeg2MultilingualSupport::*;
						match (bmMPEGCapabilities >> 8) & 0b11
						{
							0b00 => NotSupported,
							
							0b01 => SupportedAtFs,
							
							0b10 => return Err(reserved_multilingual_support_error),
							
							0b11 => SupportedAtFsAndHalfFs,
							
							_ => unreachable!(),
						}
					},
				}
			)
	}
}
