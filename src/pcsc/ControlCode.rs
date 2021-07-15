// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A control code.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct ControlCode(DWORD);

impl ControlCode
{
	#[inline(always)]
	const fn new(raw_control_code: DWORD) -> Self
	{
		Self(SCARD_CTL_CODE(raw_control_code))
	}
	
	#[inline(always)]
	const fn into_DWORD(self) -> DWORD
	{
		self.0
	}
}
