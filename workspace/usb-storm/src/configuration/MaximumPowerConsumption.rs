// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Maximum power consumption.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum MaximumPowerConsumption
{
	#[allow(missing_docs)]
	SelfPoweredAndBusPowered(MaximumPowerConsumptionMilliamps),
	
	#[allow(missing_docs)]
	SelfPowered,
	
	#[allow(missing_docs)]
	BusPowered(MaximumPowerConsumptionMilliamps),
}

impl MaximumPowerConsumption
{
	#[inline(always)]
	fn parse(configuration_descriptor: &libusb_config_descriptor, speed: Option<Speed>, is_self_powered_or_self_powered_and_bus_powered: bool) -> Result<Self, ConfigurationParseError>
	{
		#[inline(always)]
		fn milliamps(bMaxPower: u8, speed: Option<Speed>) -> MaximumPowerConsumptionMilliamps
		{
			MaximumPowerConsumptionMilliamps::new(new_non_zero_u8(bMaxPower), speed)
		}
	
		use MaximumPowerConsumption::*;
		
		let bMaxPower = configuration_descriptor.bMaxPower;
		let no_power = bMaxPower == 0;
		if is_self_powered_or_self_powered_and_bus_powered
		{
			if no_power
			{
				Ok(SelfPowered)
			}
			else
			{
				Ok(SelfPoweredAndBusPowered(milliamps(bMaxPower, speed)))
			}
		}
		else
		{
			if unlikely!(no_power)
			{
				Err(ConfigurationParseError::DeviceIsOnlyBusPoweredAndHasZeroMaximumPowerConsumption)
			}
			else
			{
				Ok(BusPowered(milliamps(bMaxPower, speed)))
			}
		}
	}
}
