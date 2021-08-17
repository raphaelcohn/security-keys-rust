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
	
	/// Done this way instead of repeated `push()` or specialized `extend()` to minimize `if` checks for each `push()` and give LLVM's loop unrolling a chance to optimize.
	fn new_populated<AUI: AsUsizeIndex, E: error::Error, MAE: FnOnce(TryReserveError) -> E, Populator: FnMut(usize) -> Result<T, E>>(length: AUI, memory_allocation_error: MAE, populator: Populator) -> Result<Self, E>;
	
	/// Push without checking capacity.
	fn push_unchecked(&mut self, value: T);
	
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
	fn new_populated<AUI: AsUsizeIndex, E: error::Error, MAE: FnOnce(TryReserveError) -> E, Populator: FnMut(usize) -> Result<T, E>>(length: AUI, memory_allocation_error: MAE, mut populator: Populator) -> Result<Self, E>
	{
		#[inline(always)]
		fn finish<T>(mut partly_initialized: Vec<MaybeUninit<T>>, length: usize) -> Vec<T>
		{
			unsafe
			{
				partly_initialized.set_len(length);
				transmute(partly_initialized)
			}
		}
		
		let length = length.as_usize();
		let mut partly_initialized: Vec<MaybeUninit<T>> = Vec::new_with_capacity(length).map_err(memory_allocation_error)?;
		
		for index in 0 .. length
		{
			match populator(index)
			{
				Err(error) =>
				{
					drop(finish(partly_initialized, index));
					return Err(error)
				}
				
				Ok(element) =>
				{
					let entry = unsafe { partly_initialized.get_unchecked_mut(index) };
					unsafe { entry.as_mut_ptr().write(element) };
				}
			}
		}
		
		Ok(finish(partly_initialized, length))
	}
	
	#[inline(always)]
	fn try_push(&mut self, value: T) -> Result<(), TryReserveError>
	{
		self.try_reserve(1)?;
		self.push(value);
		Ok(())
	}
	
	#[inline(always)]
	fn push_unchecked(&mut self, value: T)
	{
		let length = self.len();
		unsafe
		{
			let end = self.as_mut_ptr().add(length);
			write(end, value);
			self.set_len(length + 1);
		}
	}
}
