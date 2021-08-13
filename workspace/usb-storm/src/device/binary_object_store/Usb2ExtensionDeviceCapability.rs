// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// USB 2 Extension.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Usb2ExtensionDeviceCapability
{
	supports_link_power_management_protocol: bool,
}

impl Usb2ExtensionDeviceCapability
{
	/// Supports the Link Power Management (LPM) protocol.
	///
	/// Support for this is mandatory for USB Enhanced SuperSpeed devices.
	#[inline(always)]
	pub const fn supports_link_power_management_protocol(&self) -> bool
	{
		self.supports_link_power_management_protocol
	}
	
	#[inline(always)]
	fn parse(device_capability_bytes: &[u8]) -> Result<Self, Usb2ExtensionDeviceCapabilityParseError>
	{
		use Usb2ExtensionDeviceCapabilityParseError::*;
		
		const MinimumSize: usize = 4;
		if unlikely!(device_capability_bytes.len() < MinimumSize)
		{
			return Err(TooShort)
		}
		
		let supports_link_power_management_protocol =
		{
			let bmAttributes = device_capability_bytes.u32(0);
			const Mask: u32 = 0b0010;
			bmAttributes & Mask != 0
		};
		
		Ok(Self { supports_link_power_management_protocol })
	}
}
