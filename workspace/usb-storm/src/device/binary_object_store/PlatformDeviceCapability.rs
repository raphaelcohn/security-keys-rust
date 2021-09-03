// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Mandatory for hubs.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum PlatformDeviceCapability
{
	#[allow(missing_docs)]
	WebUsb(WebUsbPlatformDeviceCapability),
	
	#[allow(missing_docs)]
	Other
	{
		key: Uuid,
		
		value: Vec<u8>,
	}
}

impl PlatformDeviceCapability
{
	#[inline(always)]
	fn parse(device_capability_bytes: &[u8], device_connection: &DeviceConnection) -> Result<DeadOrAlive<Self>, PlatformDeviceCapabilityParseError>
	{
		use PlatformDeviceCapabilityParseError::*;
		
		const MinimumSize: usize = minimum_size::<20>();
		if unlikely!(device_capability_bytes.len() < MinimumSize)
		{
			return Err(TooShort)
		}
		
		let bReserved = device_capability_bytes.u8(0);
		if unlikely!(bReserved != 0)
		{
			return Err(HasReservedByteSet)
		}
		
		let key = device_capability_bytes.uuid(1);
		let value_bytes = device_capability_bytes.get_unchecked_range_safe(MinimumSize .. );
		
		const WebUsbUuid: Uuid = Uuid::from_bytes(u128::from_le_bytes([0x38, 0xB6, 0x08, 0x34, 0xA9, 0x09, 0xA0, 0x47, 0x8B, 0xFD, 0xA0, 0x76, 0x88, 0x15, 0xB6, 0x65]).to_be_bytes());
		
		use PlatformDeviceCapability::*;
		Ok
		(
			Alive
			(
				match key
				{
					WebUsbUuid => WebUsb(return_ok_if_dead!(WebUsbPlatformDeviceCapability::parse(value_bytes, device_connection)?)),
					
					_ => Other
					{
						key,
						
						value: Vec::new_from(value_bytes)?,
					}
				}
			)
		)
	}
}
