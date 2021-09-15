// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Usage page.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(transparent)]
pub struct UsagePage(NonZeroU16);

impl TryFrom<u32> for UsagePage
{
	type Error = GlobalItemParseError;
	
	#[inline(always)]
	fn try_from(data: u32) -> Result<Self, Self::Error>
	{
		use GlobalItemParseError::*;
		
		if unlikely!(data > (u16::MAX as u32))
		{
			return Err(UsagePageTooBig { data })
		}
		Self::new_checked(data as u16, UsagePageCanNotBeZero)
	}
}

impl UsagePage
{
	#[inline(always)]
	fn new_checked<E: error::Error>(usage_page: u16, usage_page_can_not_be_zero_error: E) -> Result<Self, E>
	{
		if unlikely!(usage_page == 0)
		{
			return Err(usage_page_can_not_be_zero_error)
		}
		
		Ok(Self(new_non_zero_u16(usage_page)))
	}
}
