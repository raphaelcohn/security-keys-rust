// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationAttributes
{
	supports_remote_wake_up: bool,
	
	is_self_powered_or_bus_and_self_powered: bool,
}

impl ConfigurationAttributes
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn is_self_powered_or_bus_and_self_powered(self) -> bool
	{
		self.is_self_powered_or_bus_and_self_powered
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn is_only_bus_powered(self) -> bool
	{
		!self.is_self_powered_or_bus_and_self_powered
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn supports_remote_wake_up(self) -> bool
	{
		self.supports_remote_wake_up
	}
	
}
