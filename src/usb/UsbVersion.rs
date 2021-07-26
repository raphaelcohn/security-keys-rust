// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UsbVersion
{
	major: u8,

	minor: u8,

	sub_minor: u8,
}

/// This is for a little-endian `u16`.
impl From<u16> for UsbVersion
{
	/// This is for a little-endian `u16`.
	#[inline(always)]
	fn from(binary_coded_decimal: u16) -> Self
	{
		Self::from(Version::from_bcd(binary_coded_decimal))
	}
}

impl From<Version> for UsbVersion
{
	#[inline(always)]
	fn from(version: Version) -> Self
	{
		UsbVersion
		{
			major: version.major(),
			
			minor: version.minor(),
			
			sub_minor: version.sub_minor(),
		}
	}
}
