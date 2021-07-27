// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// A vector extension traiit.
pub trait VecExt<T>: Sized
{
	/// New with capacity.
	fn new_with_capacity(length: usize) -> Result<Self, TryReserveError>;
	
	/// New buffer.
	fn new_buffer(length: usize) -> Result<Self, TryReserveError>;
	
	/// New from values.
	fn new_from(values: &[T]) -> Result<Self, TryReserveError> where T: Copy;
	
	/// Try to push.
	fn try_push(&mut self, value: T) -> Result<(), TryReserveError>;
}

impl<T> VecExt<T> for Vec<T>
{
	#[inline(always)]
	fn new_with_capacity(length: usize) -> Result<Self, TryReserveError>
	{
		let mut buffer = Vec::new();
		buffer.try_reserve_exact(length)?;
		Ok(buffer)
	}
	
	#[inline(always)]
	fn new_buffer(length: usize) -> Result<Self, TryReserveError>
	{
		let mut buffer = Self::new_with_capacity(length)?;
		unsafe { buffer.set_len(length) };
		Ok(buffer)
	}
	
	#[inline(always)]
	fn new_from(values: &[T]) -> Result<Self, TryReserveError> where T: Copy
	{
		let length = values.len();
		let mut this = Self::new_buffer(length)?;
		unsafe { this.as_mut_ptr().copy_from_nonoverlapping(values.as_ptr(), length) };
		Ok(this)
	}
	
	#[inline(always)]
	fn try_push(&mut self, value: T) -> Result<(), TryReserveError>
	{
		self.try_reserve(1)?;
		self.push(value);
		Ok(())
	}
}
