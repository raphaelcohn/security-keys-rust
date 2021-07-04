// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


struct Input<'a>(&'a [u8]);

impl<'a> Deref for Input<'a>
{
	type Target = [u8];
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		self.0
	}
}

impl<'a> Input<'a>
{
	#[inline(always)]
	fn has_remaining(&self) -> bool
	{
		!self.is_empty()
	}
	
	#[inline(always)]
	fn take(&mut self) -> Option<u8>
	{
		if self.has_remaining()
		{
			Some(self.take_one_unchecked())
		}
		else
		{
			None
		}
	}
	
	#[inline(always)]
	fn take_error<E>(&mut self, error: impl FnOnce() -> E) -> Result<u8, E>
	{
		if self.has_remaining()
		{
			Ok(self.take_one_unchecked())
		}
		else
		{
			Err(error())
		}
	}
	
	#[inline(always)]
	fn take_bytes_error<E>(&mut self, length: usize, error: impl FnOnce() -> E) -> Result<&'a [u8], E>
	{
		if self.len() >= length
		{
			let value = self.get_unchecked_range_safe(0 .. length);
			self.0 = self.0.get_unchecked_range_safe(length .. );
			Ok(value)
		}
		else
		{
			Err(error())
		}
	}
	
	#[inline(always)]
	fn take_one_unchecked(&mut self) -> u8
	{
		let value = self.get_unchecked_value_safe(0);
		self.0 = self.0.get_unchecked_range_safe(1 .. );
		value
	}
}
