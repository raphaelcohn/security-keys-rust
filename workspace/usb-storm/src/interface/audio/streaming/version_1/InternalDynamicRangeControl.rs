// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Internal Dynamic Range Control.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum InternalDynamicRangeControl
{
	#[allow(missing_docs)]
	NotSupported,
	
	#[allow(missing_docs)]
	SupportedButNotScalable,
	
	#[allow(missing_docs)]
	ScalableCommonBoostAndCutScalingValue,
	
	#[allow(missing_docs)]
	ScalableSeparateBoostAndCutScalingValue,
}

impl InternalDynamicRangeControl
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn is_supported(self) -> bool
	{
		self != InternalDynamicRangeControl::NotSupported
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn is_scalable_with_boost_and_cut_sampling_value(self) -> bool
	{
		use InternalDynamicRangeControl::*;
		
		match self
		{
			ScalableCommonBoostAndCutScalingValue | ScalableSeparateBoostAndCutScalingValue => true,
			
			_ => false,
		}
	}
	
	#[inline(always)]
	fn from_2_bits(bits: u8) -> Self
	{
		use InternalDynamicRangeControl::*;
		
		match bits & 0b11
		{
			0b00 => NotSupported,
			
			0b01 => SupportedButNotScalable,
			
			0b10 => ScalableCommonBoostAndCutScalingValue,
			
			0b11 => ScalableSeparateBoostAndCutScalingValue,
			
			_ => unreachable!(),
		}
	}
}
