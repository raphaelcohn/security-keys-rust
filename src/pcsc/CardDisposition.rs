// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// `#[repr(DWORD)]`.
#[cfg_attr(any(target_os = "macos", target_os = "windows"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "32"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "64"), repr(u64))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum CardDisposition
{
	/// Don’t alter card state.
	Leave = SCARD_LEAVE_CARD,
	
	/// Reset the card.
	Reset = SCARD_RESET_CARD,
	
	/// Unpower and terminate access to the card.
	///
	/// Does a 'cold reset': powers down card then powers it up.
	ColdReset = SCARD_UNPOWER_CARD,
	
	/// Eject the card from the reader.
	Eject = SCARD_EJECT_CARD,

	// /// Used to indicate that a sophisticated commercial reader should move the card to the confiscation bin and not return it to the user.
	// Confiscate = SCARD_CONFISCATE_CARD,
}

impl CardDisposition
{
	#[inline(always)]
	const fn into_DWORD(self) -> DWORD
	{
		unsafe { transmute(self) }
	}
}
