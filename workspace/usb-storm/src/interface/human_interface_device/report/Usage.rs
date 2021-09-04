// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Usage.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Usage
{
	usage_page: Option<UsagePage>,

	usage_identifier: UsageIdentifier,
}

impl TryClone for Usage
{
	#[inline(always)]
	fn try_clone(&self) -> Result<Self, TryReserveError>
	{
		Ok(*self)
	}
}

impl Usage
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn usage_page(&self) -> Option<UsagePage>
	{
		self.usage_page
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn usage_identifier(&self) -> UsageIdentifier
	{
		self.usage_identifier
	}
	
	#[inline(always)]
	fn parse(data: u32, was_32_bits_wide: bool) -> Self
	{
		Self
		{
			usage_page: if was_32_bits_wide
			{
				Some((data >> 16) as u16)
			}
			else
			{
				None
			},
		
			usage_identifier: data as u16,
		}
	}
	
}
