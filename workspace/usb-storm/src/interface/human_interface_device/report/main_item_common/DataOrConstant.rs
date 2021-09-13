// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Data or constant.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u8)]
pub enum DataOrConstant
{
	#[allow(missing_docs)]
	Data = 0,
	
	#[allow(missing_docs)]
	Constant = 1,
}

impl From<bool> for DataOrConstant
{
	#[inline(always)]
	fn from(value: bool) -> Self
	{
		unsafe { transmute(value as u8) }
	}
}

impl Into<bool> for DataOrConstant
{
	#[inline(always)]
	fn into(self) -> bool
	{
		unsafe { transmute(self as u8) }
	}
}
