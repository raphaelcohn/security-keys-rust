// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct CardReaderNamesIterator<'buffer>
{
	slice: &'buffer [u8],
	
	next_c_string_index: usize,
}

impl<'buffer> Iterator for CardReaderNamesIterator<'buffer>
{
	type Item = CardReaderName<'buffer>;
	
	#[inline(always)]
	fn next(&mut self) -> Option<Self::Item>
	{
		let slice = self.slice.get_unchecked_range_safe(self.next_c_string_index .. );
		
		let null_index = CardReaderNames::null_index(slice);
		if unlikely!(null_index == 0)
		{
			return None
		}
		
		let result = Some(CardReaderNames::wrap_reader_name(slice, null_index));
		self.next_c_string_index = CardReaderNames::next_c_string_index(null_index);
		result
	}
	
	#[inline(always)]
	fn size_hint(&self) -> (usize, Option<usize>)
	{
		if unlikely!(self.slice.len() == 1)
		{
			(0, Some(0))
		}
		else
		{
			(1, None)
		}
	}
}
