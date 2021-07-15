// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Card reader names.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct CardReaderNames(CardReaderNamesBuffer);

impl CardReaderNames
{
	const ArrayEndMarkerIsEmptyCString: u8 = 0x00;
	
	#[inline(always)]
	pub(in crate::pcsc) fn from_valid_buffer(mut reader_names: CardReaderNamesBuffer, reader_names_length: DWORD) -> Self
	{
		let reader_names_length = reader_names_length as usize;
		debug_assert_ne!(reader_names_length, 0);
		
		unsafe { reader_names.set_len(reader_names_length) };
		
		debug_assert_eq!(reader_names.get_unchecked_value_safe(reader_names_length - 1), Self::ArrayEndMarkerIsEmptyCString, "reader_names array of CStrings is not terminated by an empty CString");
		Self(reader_names)
	}
	
	#[inline(always)]
	pub(in crate::pcsc) fn from_empty_buffer(mut reader_names: CardReaderNamesBuffer) -> Self
	{
		debug_assert_eq!(reader_names.len(), 0);
		
		unsafe { reader_names.set_len(1) };
		reader_names.set_unchecked_mut_safe(0, Self::ArrayEndMarkerIsEmptyCString);
		return Self(reader_names)
	}
	
	/// Iterate.
	#[inline(always)]
	pub fn iterate(&self) -> CardReaderNamesIterator
	{
		CardReaderNamesIterator
		{
			slice: self.slice(),
		
			next_c_string_index: 0,
		}
	}
	
	/// Create card reader states from all card reader names.
	#[inline(always)]
	pub fn create_card_reader_states(&self) -> CardReaderStates<()>
	{
		let mut card_reader_states = CardReaderStates::new();
		self.use_all_card_reader_names(|card_reader_name|
		{
			card_reader_states.push_reader_state(CardReaderEventName::StateChange(card_reader_name), None, false)
		});
		card_reader_states
	}
	
	/// Iterate, efficiently.
	#[inline(always)]
	pub fn use_all_card_reader_names<'buffer, CardReaderNameUser: FnMut(CardReaderName<'buffer>)>(&'buffer self, mut card_reader_name_user: CardReaderNameUser)
	{
		let mut slice = self.slice();
		let mut null_index = Self::null_index(slice);
		while likely!(null_index != 0)
		{
			let reader_name = Self::wrap_reader_name(slice, null_index);
			card_reader_name_user(reader_name);
			
			slice = slice.get_unchecked_range_safe(Self::next_c_string_index(null_index) .. );
			null_index = Self::null_index(slice);
		}
	}
	
	#[inline(always)]
	fn slice(&self) -> &[u8]
	{
		self.0.as_slice()
	}
	
	#[inline(always)]
	fn null_index(slice: &[u8]) -> usize
	{
		memchr(b'\0', slice).expect("The final item should be an empty CString, not just empty")
	}
	
	#[inline(always)]
	fn wrap_reader_name(slice: &[u8], null_index: usize) -> CardReaderName
	{
		CardReaderName::wrap_buffer(slice, null_index)
	}
	
	#[inline(always)]
	const fn next_c_string_index(null_index: usize) -> usize
	{
		null_index + 1
	}
}
