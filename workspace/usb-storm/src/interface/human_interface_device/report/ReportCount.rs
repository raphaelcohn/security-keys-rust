// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Report count.
///
/// Think of this value as the number of fields.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(transparent)]
pub struct ReportCount(NonZeroU16);

impl Into<NonZeroU16> for ReportCount
{
	#[inline(always)]
	fn into(self) -> NonZeroU16
	{
		self.0
	}
}

impl Into<u16> for ReportCount
{
	#[inline(always)]
	fn into(self) -> u16
	{
		self.u16()
	}
}

impl Into<NonZeroU32> for ReportCount
{
	#[inline(always)]
	fn into(self) -> NonZeroU32
	{
		new_non_zero_u32(self.u32())
	}
}

impl Into<u32> for ReportCount
{
	#[inline(always)]
	fn into(self) -> u32
	{
		self.u32()
	}
}

impl TryFrom<u32> for ReportCount
{
	type Error = ReportCountParseError;
	
	#[inline(always)]
	fn try_from(data: u32) -> Result<Self, Self::Error>
	{
		use ReportCountParseError::*;
		
		if unlikely!(data == 0)
		{
			return Err(ReportCountCanNotBeZero)
		}
		
		if unlikely!(data > ReportCount::HID_MAX_USAGES)
		{
			return Err(ReportCountTooLarge { data })
		}
		
		Ok(Self(new_non_zero_u16(data as u16)))
	}
}

impl ReportCount
{
	// This constant is from Linux.
	const HID_MAX_USAGES: u32 = 12288;
	
	/// Inclusive maximum.
	pub const InclusiveMaximum: Self = Self(new_non_zero_u16(Self::HID_MAX_USAGES as u16));
	
	#[inline(always)]
	fn u16(self) -> u16
	{
		self.0.get()
	}
	
	#[inline(always)]
	fn u32(self) -> u32
	{
		self.u16() as u32
	}
}
