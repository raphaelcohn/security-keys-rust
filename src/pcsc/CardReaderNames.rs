// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct CardReaderNames(Option<Buffer>);

impl CardReaderNames
{
	const Empty: Self = Self(None);
	
	#[inline(always)]
	const fn new(buffer: Buffer) -> Self
	{
		Self(Some(buffer))
	}
	
	#[inline(always)]
	pub(crate) fn iterate(&self) -> CardReaderNamesIterator
	{
		CardReaderNamesIterator
		{
			slice: self.slice(),
		
			next_c_string_index: 0,
		}
	}
	
	#[inline(always)]
	pub(crate) fn create_card_reader_states(&self) -> CardReaderStates<()>
	{
		let mut card_reader_states = CardReaderStates::new();
		self.use_all_card_reader_names(|card_reader_name|
		{
			card_reader_states.push_reader_state(CardReaderEventName::StateChange(card_reader_name), None, false)
		});
		card_reader_states
	}
	
	#[inline(always)]
	pub(crate) fn use_all_card_reader_names<'buffer, CardReaderNameUser: FnMut(CardReaderName<'buffer>)>(&'buffer self, mut card_reader_name_user: CardReaderNameUser)
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
		match self.0
		{
			None =>
			{
				static NoReadersAvailable: &'static [u8] = b"\0";
				NoReadersAvailable
			}
			
			Some(ref buffer) => buffer.buffer.as_slice(),
		}
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
