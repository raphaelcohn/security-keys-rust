// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// The class `CLA` used in APDU commands before a device is configured when using the ISO 7816 T=0 protocol.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u8)]
pub enum T0ProtocolUnconfiguredClass
{
	#[allow(missing_docs)]
	Zero = 0x00,
	
	/// Echos what is sent.
	Echo = 0xFF,
}

impl T0ProtocolUnconfiguredClass
{
	#[inline(always)]
	fn parse(class: u8, error: impl FnOnce(u8) -> SmartCardInterfaceAdditionalDescriptorParseError) -> Result<Self, SmartCardInterfaceAdditionalDescriptorParseError>
	{
		use T0ProtocolUnconfiguredClass::*;
		let parsed = match class
		{
			0x00 => Zero,
			
			0xFF => Echo,
			
			unsupported @ _ => return Err(error(unsupported)),
		};
		Ok(parsed)
	}
}
