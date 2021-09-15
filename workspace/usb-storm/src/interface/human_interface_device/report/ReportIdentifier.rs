// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// 1 to 255.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[repr(transparent)]
pub struct ReportIdentifier(NonZeroU8);

impl Into<NonZeroU8> for ReportIdentifier
{
	#[inline(always)]
	fn into(self) -> NonZeroU8
	{
		self.0
	}
}

impl From<NonZeroU8> for ReportIdentifier
{
	#[inline(always)]
	fn from(value: NonZeroU8) -> Self
	{
		Self(value)
	}
}

impl TryFrom<u32> for ReportIdentifier
{
	type Error = GlobalItemParseError;
	
	#[inline(always)]
	fn try_from(data: u32) -> Result<Self, Self::Error>
	{
		use GlobalItemParseError::*;
		
		if unlikely!(data == 0)
		{
			return Err(ReportIdentifierZeroIsReserved)
		}
		
		// This value is specified in the HID parser 'white paper' and in Linux as `HID_MAX_IDS`.
		if unlikely!(data >= 256)
		{
			return Err(ReportIdentifierTooLarge { data })
		}
		
		Ok(Self(new_non_zero_u8(data as u8)))
	}
}
