// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Only present if a SuperSpeed EndPoint Additional Descriptor is present.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuperSpeedInterrupt
{
	pub(super) maximum_number_of_packets_that_can_burst_at_a_time: NonZeroU4,
	
	pub(super) total_number_of_bytes_transfered_every_service_interval: u16,
}

impl SuperSpeedInterrupt
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_number_of_packets_that_can_burst_at_a_time(&self) -> NonZeroU4
	{
		self.maximum_number_of_packets_that_can_burst_at_a_time
	}
	
	/// Total number of bytes this end point will transfer every service interval (SI).
	#[inline(always)]
	pub const fn total_number_of_bytes_transfered_every_service_interval(&self) -> u16
	{
		self.total_number_of_bytes_transfered_every_service_interval
	}
}
