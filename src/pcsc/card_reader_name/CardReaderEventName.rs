// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A reader name should be 128 bytes, including the trailing ASCII NULL.
///
/// There are latent bugs in PCSC that permit a reader name of 128 bytes *excluding* the trailing ASCII NULL.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum CardReaderEventName<'a>
{
	/// A regular reader name used for state changes.
	StateChange(CardReaderName<'a>),
	
	/// A special reader name used to detect if card readers are added or removed; something of a hack in PC/SC lite.
	AddedOrRemoved,
}

impl<'a> CardReaderEventName<'a>
{
	#[inline(always)]
	pub(in crate::pcsc) fn raw_reader_name_or_special(self) -> *const c_char
	{
		use self::CardReaderEventName::*;
		
		match self
		{
			StateChange(card_reader_name) => card_reader_name.as_ptr(),
			
			AddedOrRemoved => Self::special_reader_name_for_detecting_card_reader_insertions_and_removals(),
		}
	}
	
	#[inline(always)]
	pub(in crate::pcsc) fn recreate(raw_reader_name_or_special: *const c_char) -> Self
	{
		use self::CardReaderEventName::*;
		
		if unlikely!(raw_reader_name_or_special == Self::special_reader_name_for_detecting_card_reader_insertions_and_removals())
		{
			AddedOrRemoved
		}
		else
		{
			StateChange(CardReaderName::new_unchecked(raw_reader_name_or_special))
		}
	}
	
	#[inline(always)]
	fn special_reader_name_for_detecting_card_reader_insertions_and_removals() -> *const c_char
	{
		static PlugAndPlayNotification: &'static [u8] = b"\\\\?PnP?\\Notification\0";
		PlugAndPlayNotification.as_ptr() as *const c_char
	}
	
	#[inline(always)]
	pub(in crate::pcsc) fn state_change(self) -> CardReaderName<'a>
	{
		use self::CardReaderEventName::*;
		
		match self
		{
			StateChange(state_change) => state_change,
			
			AddedOrRemoved => panic!("Was not StateChange"),
		}
	}
}
