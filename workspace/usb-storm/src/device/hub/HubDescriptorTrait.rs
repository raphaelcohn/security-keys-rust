// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A hub descriptor trait.
pub trait HubDescriptorTrait
{
	#[allow(missing_docs)]
	type DPS: DownstreamPortSetting;
	
	#[allow(missing_docs)]
	fn logical_power_switching_mode(&self) -> LogicalPowerSwitchingMode;
	
	#[allow(missing_docs)]
	fn is_part_of_a_compound_device(&self) -> bool;
	
	#[allow(missing_docs)]
	fn overcurrent_protection_mode(&self) -> OvercurrentProtectionMode;
	
	/// Will never return more than 510ms (`255 × 2`).
	///
	/// EHCI 1.0 has a maximum value of 20ms.
	fn time_in_milliseconds_from_power_on_a_port_until_power_is_good_on_that_port(&self) -> u16;
	
	/// For USB 3 hubs, the inclusive maximum value is 1020 milliamps, with values in 4 milliamp steps.
	/// For USB 2 hubs, the inclusive maximum value is 255 milliamps, in 1 milliamp steps.
	fn maximum_current_requirement_in_milliamps(&self) -> u16;
	
	#[allow(missing_docs)]
	fn downstream_ports(&self) -> &DownstreamPorts<Self::DPS>;
}
