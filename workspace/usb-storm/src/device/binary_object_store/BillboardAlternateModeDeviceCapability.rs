// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An USB 3.0 concept.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BillboardAlternateModeDeviceCapability
{
	index: u8,

	vdo_or_usb_4_eudo: u32,
}

impl BillboardAlternateModeDeviceCapability
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn index(&self) -> u8
	{
		self.index
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn vdo_or_usb_4_eudo(&self) -> u32
	{
		self.vdo_or_usb_4_eudo
	}
	
	#[inline(always)]
	fn parse(device_capability_bytes: &[u8]) -> Result<Self, BillboardAlternateModeDeviceCapabilityParseError>
	{
		use BillboardAlternateModeDeviceCapabilityParseError::*;
		
		if unlikely!(device_capability_bytes.len() < 5)
		{
			return Err(ShorterThanMinimumSize)
		}
		
		Ok
		(
			Self
			{
				index:
				{
					let index = device_capability_bytes.u8(0);
					if unlikely!(index >= BillboardAlternateMode::MAX_NUM_ALT_OR_USB4_MODE)
					{
						return Err(InvalidIndex { index })
					}
					index
				},
				
				vdo_or_usb_4_eudo: device_capability_bytes.u32(1),
			}
		)
	}
}
