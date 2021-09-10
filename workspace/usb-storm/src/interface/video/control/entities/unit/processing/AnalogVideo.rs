// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Digital multiplier.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalogVideo
{
	analog_video_standards: WrappedBitFlags<AnalogVideoStandard>,
	
	lock_status: bool,
}

impl AnalogVideo
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn analog_video_standards(&self) -> WrappedBitFlags<AnalogVideoStandard>
	{
		self.analog_video_standards
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn lock_status(&self) -> bool
	{
		self.lock_status
	}
	
	#[inline(always)]
	fn parse(entity_body: &[u8], controls_bit_map: u32, index_after_controls: usize, specification_version: Version) -> Result<Option<Self>, ProcessingUnitEntityParseError>
	{
		let outcome = if likely!(specification_version.is_1_1_or_greater())
		{
			let analog_video_standard = (controls_bit_map & (1 << 16)) != 0;
			let analog_video_lock_status = (controls_bit_map & (1 << 17)) != 0;
			
			let bmVideoStandards = entity_body.optional_non_zero_u8(entity_index_non_constant(index_after_controls + 1));
			match (bmVideoStandards, analog_video_standard, analog_video_lock_status)
			{
				(Some(bmVideoStandards), true, lock_status @ _) => Some
				(
					Self
					{
						analog_video_standards: WrappedBitFlags::from_bits_truncate(bmVideoStandards.get()),
						
						lock_status
					}
				),
				
				(None, false, false) => None,
				
				_ => return Err(ProcessingUnitEntityParseError::InvalidCombinationOfAnalogVideoValues { bmVideoStandards, analog_video_standard, analog_video_lock_status })
			}
		}
		else
		{
			None
		};
		Ok(outcome)
	}
}
