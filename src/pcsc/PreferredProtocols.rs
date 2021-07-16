// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// `#[repr(NonZero(DWORD))]`.
#[cfg_attr(any(target_os = "ios", target_os = "macos", target_os = "windows"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "ios", target_os = "macos", target_os = "windows")), target_pointer_width = "32"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "ios", target_os = "macos", target_os = "windows")), target_pointer_width = "64"), repr(u64))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum PreferredProtocols
{
	/// `T = 0` protocol; obsolescent.
	T0 = SCARD_PROTOCOL_T0,
	
	/// `T = 1` protocol; frame-based; supported by most cards as of 2021.
	T1 = SCARD_PROTOCOL_T1,
	
	/// A raw protocol; not ideal.
	RAW = SCARD_PROTOCOL_RAW,
	
	/// Let the card reader or driver choose either `T = 0` or `T = 1`.
	///
	/// Ideal choice.
	T0_or_T1 = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
}

impl Default for PreferredProtocols
{
	#[inline(always)]
	fn default() -> Self
	{
		PreferredProtocols::T0_or_T1
	}
}

impl PreferredProtocols
{
	#[inline(always)]
	const fn into_DWORD(self) -> DWORD
	{
		unsafe { transmute(self) }
	}
}

