// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A reusable buffer for allocations up to 2^16 - 1.
#[derive(Debug)]
pub struct ReusableBuffer(Vec<MaybeUninit<u8>>);

impl ReusableBuffer
{
	/// Create a new instance.
	#[inline(always)]
	pub fn new() -> Result<Self, TryReserveError>
	{
		const MaximumSize: usize = u16::MAX as usize;
		
		let buffer = if cfg!(debug_assertions)
		{
			Vec::new_populated(MaximumSize, |cause| cause, |_|
			{
				Ok(MaybeUninit::zeroed())
			})
		}
		else
		{
			Vec::new_buffer(MaximumSize)
		}?;
		
		Ok(Self(buffer))
	}
	
	#[inline(always)]
	pub(crate) fn as_maybe_uninit_slice(&mut self) -> &mut [MaybeUninit<u8>]
	{
		self.0.as_mut_slice()
	}
	
	#[inline(always)]
	pub(crate) fn as_maybe_uninit_slice_of_length(&mut self, length: u16) -> &mut [MaybeUninit<u8>]
	{
		self.0.as_mut_slice().get_unchecked_range_mut_safe(.. (length as usize))
	}
}
