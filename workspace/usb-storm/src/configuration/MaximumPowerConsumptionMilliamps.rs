// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Maximum power consumption in milliamps.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[repr(transparent)]
pub struct MaximumPowerConsumptionMilliamps(NonZeroU16);

impl MaximumPowerConsumptionMilliamps
{
	/// Range is `2 .. = 510` for low, full and high speed devices, in multiples of 2, and `8 .. = 2040` in multiples of 8 for Gen X (USB 3) speed devices.
	#[inline(always)]
	pub const fn milliamps(self) -> NonZeroU16
	{
		self.0
	}
	
	#[inline(always)]
	fn new(bMaxPower: NonZeroU8, speed: Option<Speed>) -> Self
	{
		const SlowMilliampsPerUnit: u16 = 2;
		
		let milliamps_per_unit = if let Some(speed) = speed
		{
			if speed.is_gen_x_speed()
			{
				8
			}
			else
			{
				SlowMilliampsPerUnit
			}
		}
		else
		{
			SlowMilliampsPerUnit
		};
		
		
		let milliamps = (bMaxPower.get() as u16) * milliamps_per_unit;
		Self(new_non_zero_u16(milliamps))
	}
}
