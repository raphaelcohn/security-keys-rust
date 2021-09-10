// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Capability set.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MicrosoftOperatingSystemPlatformDeviceCapabilitySet
{
	total_length: u16,
	
	vendor_code: MicrosoftVendorCode,
	
	alternate_enumeration_code: Option<NonZeroU8>,
}

impl MicrosoftOperatingSystemPlatformDeviceCapabilitySet
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn total_length(&self) -> u16
	{
		self.total_length
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn vendor_code(&self) -> MicrosoftVendorCode
	{
		self.vendor_code
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn alternate_enumeration_code(&self) -> Option<NonZeroU8>
	{
		self.alternate_enumeration_code
	}
	
	#[inline(always)]
	fn parse(set_bytes: &[u8]) -> Result<(WindowsVersion, Self), MicrosoftOperatingSystemPlatformDeviceCapabilityParseError>
	{
		Ok
		(
			(
				WindowsVersion::parse(set_bytes.u32(0))?,
				
				Self
				{
					total_length: set_bytes.u16(4),
				
					vendor_code: set_bytes.u8(6),
				
					alternate_enumeration_code: set_bytes.optional_non_zero_u8(7),
				},
			)
		)
	}
}
