// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Downstream ports.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DownstreamPorts<DPS: DownstreamPortSetting>(Vec<DPS>);

impl<DPS: DownstreamPortSetting> DownstreamPorts<DPS>
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn setting(&self, port_number: PortNumber) -> DPS
	{
		debug_assert!(port_number.get() <= self.number_of_downstream_ports());
		self.0.get_unchecked_value_safe(port_number.get() - 1)
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn number_of_downstream_ports(&self) -> u8
	{
		self.0.len() as u8
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn maximum_port_number(&self) -> Option<NonZeroU8>
	{
		NonZeroU8::new(self.number_of_downstream_ports())
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn iterate(&self) -> impl Iterator<Item=(PortNumber, DPS)> + '_
	{
		self.0.iter().enumerate().map(|(index, port_setting)| (new_non_zero_u8((index as u8) + 1), *port_setting))
	}
}

impl DownstreamPorts<Version2DownstreamPortSetting>
{
}
