// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[cfg(target_os = "windows")]
#[inline(always)]
pub(in crate::pcsc) const fn SCARD_CTL_CODE(code: DWORD) -> DWORD
{
	0x0031_0000 | (code << 2)
}

#[cfg(not(target_os = "windows"))]
#[inline(always)]
pub(in crate::pcsc) const fn SCARD_CTL_CODE(code: DWORD) -> DWORD
{
	0x4200_0000 + code
}
