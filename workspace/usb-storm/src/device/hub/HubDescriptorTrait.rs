// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A hub descriptor trait.
pub trait HubDescriptorTrait
{
	#[allow(missing_docs)]
	type PS: PortSetting;
	
	#[allow(missing_docs)]
	fn logical_power_switching_mode(&self) -> LogicalPowerSwitchingMode;
	
	#[allow(missing_docs)]
	fn is_part_of_a_compound_device(&self) -> bool;
	
	#[allow(missing_docs)]
	fn overcurrent_protection_mode(&self) -> OvercurrentProtectionMode;
	
	/// Maximum value is 510.
	fn time_in_milliseconds_from_power_on_a_port_until_power_is_good_on_that_port(&self) -> u16;
	
	#[allow(missing_docs)]
	fn ports_settings(&self) -> &PortsSetting<Self::PS>;
}
