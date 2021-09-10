// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Billboard device container failed because information.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BillboardDeviceContainerFailedBecause
{
	lack_of_power: bool,
	
	no_power_delivery_communication: bool,
}

impl BillboardDeviceContainerFailedBecause
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn lack_of_power(&self) -> bool
	{
		self.lack_of_power
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn no_power_delivery_communication(&self) -> bool
	{
		self.lack_of_power
	}
	
	#[inline(always)]
	fn parse(version: Version, device_capability_bytes: &[u8]) -> Option<Self>
	{
		if version.is_0x0110_or_greater()
		{
			let bAdditionalFailInfo = device_capability_bytes.u8(capability_descriptor_index::<42>());
			Some
			(
				Self
				{
					lack_of_power: bAdditionalFailInfo & 0b01 != 0,
					
					no_power_delivery_communication: bAdditionalFailInfo & 0b10 != 0,
				}
			)
		}
		else
		{
			None
		}
	}
}
