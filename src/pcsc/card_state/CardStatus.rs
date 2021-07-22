// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// `#[repr(DWORD)]`.
#[cfg_attr(any(target_os = "ios", target_os = "macos", target_os = "windows"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "ios", target_os = "macos", target_os = "windows")), target_pointer_width = "32"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "ios", target_os = "macos", target_os = "windows")), target_pointer_width = "64"), repr(u64))]
#[derive(EnumIter)]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum CardStatus
{
	/// Unknown.
	Unknown = SCARD_UNKNOWN,
	
	/// Absent.
	Absent = SCARD_ABSENT,
	
	/// Present.
	Present = SCARD_PRESENT,
	
	/// Swallowed.
	Swallowed = SCARD_SWALLOWED,
	
	/// Powered.
	Powered = SCARD_POWERED,
	
	/// Negotiable.
	Negotiable = SCARD_NEGOTIABLE,

	/// Specific.
	Specific = SCARD_SPECIFIC,
}

impl CardStatus
{
	#[cfg(target_os = "windows")]
	#[inline(always)]
	fn convert(enumeration_on_windows_and_bit_field_on_pcsclite: u16) -> HashSet<CardStatus>
	{
		let raw_status = enumeration_on_windows_and_bit_field_on_pcsclite as DWORD;
		let mut card_reader_statuses = HashSet::with_capacity(1);
		card_reader_statuses.insert(unsafe { transmute(raw_status) });
		card_reader_statuses
	}
	
	#[cfg(not(target_os = "windows"))]
	#[inline(always)]
	pub(in crate::pcsc) fn convert(enumeration_on_windows_and_bit_field_on_pcsclite: u16) -> HashSet<CardStatus>
	{
		let raw_status = enumeration_on_windows_and_bit_field_on_pcsclite as DWORD;
		let mut card_reader_statuses = HashSet::with_capacity(1);
		for potential_card_reader_status in Self::iter()
		{
			if unlikely!(raw_status & potential_card_reader_status.into_DWORD() != 0)
			{
				let _ = card_reader_statuses.insert(potential_card_reader_status);
			}
		}
		card_reader_statuses
	}
	
	#[inline(always)]
	const fn into_DWORD(self) -> DWORD
	{
		unsafe { transmute(self) }
	}
}
