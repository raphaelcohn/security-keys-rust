// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct Buffer
{
	buffer: ManuallyDrop<Vec<u8>>,

	buffer_provider: Rc<BufferProvider>
}

impl Drop for Buffer
{
	#[inline(always)]
	fn drop(&mut self)
	{
		let buffer = unsafe { ManuallyDrop::take(&mut self.buffer) };
		self.buffer_provider.gift(buffer)
	}
}

impl Buffer
{
	#[inline(always)]
	fn c_string_pointer_mut(&mut self) -> *mut c_char
	{
		self.buffer.as_mut_ptr() as *mut c_char
	}
	
	#[inline(always)]
	fn shorten(&mut self, same_or_shorter_length: DWORD)
	{
		let length = same_or_shorter_length as usize;
		self.buffer.set_length(length);
	}
}
