// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Digital multiplier.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DigitalMultiplier
{
	multiplier_scaled_by_a_factor_of_100: NonZeroU16,
	
	limit: bool,
}

impl DigitalMultiplier
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn multiplier_scaled_by_a_factor_of_100(&self) -> NonZeroU16
	{
		self.multiplier_scaled_by_a_factor_of_100
	}

	/// Always false for specification version 1.0.
	#[inline(always)]
	pub const fn limit(&self) -> bool
	{
		self.limit
	}

	#[inline(always)]
	fn parse(entity_body: &[u8], controls_bit_map: u32, specification_version: Version) -> Result<Option<Self>, ProcessingUnitEntityParseError>
	{
		let wMaxMultiplier = entity_body.optional_non_zero_u16(entity_index::<5>());
		let outcome = if likely!(specification_version.is_1_1_or_greater())
		{
			let digital_multiplier_supported = (controls_bit_map & (1 << 14)) != 0;
			let digital_multiplier_limit = (controls_bit_map & (1 << 15)) != 0;
			
			match (wMaxMultiplier, digital_multiplier_supported, digital_multiplier_limit)
			{
				(Some(multiplier_scaled_by_a_factor_of_100), true, limit @ _) => Some
				(
					Self
					{
						multiplier_scaled_by_a_factor_of_100,
						
						limit
					}
				),
				
				(None, false, false) => None,
				
				_ => return Err(ProcessingUnitEntityParseError::InvalidCombinationOfDigitalMultiplierValues { wMaxMultiplier, digital_multiplier_supported, digital_multiplier_limit })
			}
		}
		else
		{
			wMaxMultiplier.map(|multiplier_scaled_by_a_factor_of_100| Self
			{
				multiplier_scaled_by_a_factor_of_100,
			
				limit: false,
			})
		};
		Ok(outcome)
	}
}
