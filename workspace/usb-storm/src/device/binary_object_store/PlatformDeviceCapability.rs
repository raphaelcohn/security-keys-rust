// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Mandatory for hubs.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformDeviceCapability
{
	key: Uuid,

	value: Vec<u8>,
}

impl PlatformDeviceCapability
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn key(&self) -> Uuid
	{
		self.key
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn value(&self) -> &[u8]
	{
		&self.value
	}
	
	#[inline(always)]
	fn parse(device_capabilities_bytes: &[u8]) -> Result<Self, PlatformDeviceCapabilityParseError>
	{
		use PlatformDeviceCapabilityParseError::*;
		
		const MinimumSize: usize = 20 - 3;
		if unlikely!(device_capabilities_bytes.len() < MinimumSize)
		{
			return Err(TooShort)
		}
		
		let bReserved = device_capabilities_bytes.u8_unadjusted(0);
		if unlikely!(bReserved != 0)
		{
			return Err(HasReservedByteSet)
		}
		
		Ok
		(
			Self
			{
				key: device_capabilities_bytes.uuid_unadjusted(1),
			
				value: Vec::new_from(device_capabilities_bytes.get_unchecked_range_safe(MinimumSize .. ))?,
			}
		)
	}
}
