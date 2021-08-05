// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Reserved.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedDeviceCapability
{
	device_capability_type_code: u8,
	
	device_capability_bytes: Vec<u8>,
}

impl ReservedDeviceCapability
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn device_capability_type_code(&self) -> u8
	{
		self.device_capability_type_code
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn device_capability_bytes(&self) -> &[u8]
	{
		&self.device_capability_bytes
	}
	
	#[inline(always)]
	fn parse(bDescriptorType: u8, device_capability_bytes: &[u8]) -> Result<Self, TryReserveError>
	{
		Ok
		(
			Self
			{
				device_capability_type_code: bDescriptorType,
				
				device_capability_bytes: Vec::new_from(device_capability_bytes)?,
			}
		)
	}
}
