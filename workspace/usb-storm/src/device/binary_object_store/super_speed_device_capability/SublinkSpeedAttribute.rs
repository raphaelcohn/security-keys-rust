// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Sublink speed attribute.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SublinkSpeedAttribute
{
	/// This field defines the base 10 exponent times 3, that shall be applied to the Lane Speed Mantissa (LSM) when calculating the maximum bit rate for this `SublinkSpeedAttribute`.
	lane_speed_exponent: BitRate,
	
	sublink_protocol: SublinkProtocol,
	
	lane_speed_mantissa: u16,
}

impl SublinkSpeedAttribute
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_bit_rate(&self) -> u64
	{
		self.scalar() * (self.lane_speed_mantissa as u64)
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn sublink_protocol(&self) -> SublinkProtocol
	{
		self.sublink_protocol
	}
	
	#[inline(always)]
	const fn scalar(&self) -> u64
	{
		let lane_speed_exponent = (self.lane_speed_exponent as u8 as u32) * 3;
		10u64.pow(lane_speed_exponent)
	}
}
