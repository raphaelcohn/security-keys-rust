// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Report size.
///
/// This value is a number of bits.
/// Think of it as the width of a field in bits.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[repr(transparent)]
pub struct ReportSize(NonZeroU16);

impl Into<NonZeroU16> for ReportSize
{
	#[inline(always)]
	fn into(self) -> NonZeroU16
	{
		self.0
	}
}

impl Into<u16> for ReportSize
{
	#[inline(always)]
	fn into(self) -> u16
	{
		self.u16()
	}
}

impl Into<NonZeroU32> for ReportSize
{
	#[inline(always)]
	fn into(self) -> NonZeroU32
	{
		new_non_zero_u32(self.u32())
	}
}

impl Into<u32> for ReportSize
{
	#[inline(always)]
	fn into(self) -> u32
	{
		self.u32()
	}
}

impl TryFrom<u32> for ReportSize
{
	type Error = ReportSizeParseError;
	
	#[inline(always)]
	fn try_from(data: u32) -> Result<Self, Self::Error>
	{
		// This check is based on that in Linux in `drivers/hid/hid_core.c`, starting from `case HID_GLOBAL_ITEM_TAG_REPORT_SIZE`.
		if unlikely!(data > 256)
		{
			return Err(ReportSizeParseError::ReportSizeGreaterThan256Bytes { data })
		}
		Ok(Self(new_non_zero_u16(data as u16)))
	}
}

impl ReportSize
{
	/// Inclusive maximum is 256.
	pub const InclusiveMaximum: Self = Self(new_non_zero_u16(256));
	
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
