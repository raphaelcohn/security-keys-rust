// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// `#[repr(NonZero(DWORD))]`.
#[cfg_attr(any(target_os = "macos", target_os = "windows"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "32"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "64"), repr(u64))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum PreferredProtocols
{
	T0 = SCARD_PROTOCOL_T0,
	
	T1 = SCARD_PROTOCOL_T1,
	
	RAW = SCARD_PROTOCOL_RAW,
	
	T0_or_T1 = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
}

impl PreferredProtocols
{
	#[inline(always)]
	const fn into_DWORD(self) -> DWORD
	{
		unsafe { transmute(self) }
	}
}

