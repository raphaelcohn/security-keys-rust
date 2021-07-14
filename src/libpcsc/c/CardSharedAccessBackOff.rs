// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct CardSharedAccessBackOff
{
	remaining_attempts: usize,
	
	maximum_sleep_nanoseconds: NonZeroU64,
	
	current_sleep_nanoseconds: NonZeroU64,
}

impl CardSharedAccessBackOff
{
	#[inline(always)]
	pub(crate) const fn new(remaining_attempts: usize, maximum_sleep_nanoseconds: NonZeroU64, initial_sleep_nanoseconds: NonZeroU64) -> Self
	{
		Self
		{
			remaining_attempts,
			
			maximum_sleep_nanoseconds,
		
			current_sleep_nanoseconds: initial_sleep_nanoseconds,
		}
	}
	
	#[inline(always)]
	fn sleep(&mut self) -> bool
	{
		self.remaining_attempts = match self.remaining_attempts.checked_sub(1)
		{
			None => return false,
			
			Some(remaining_attempts) => remaining_attempts,
		};
		let current_sleep_nanoseconds = max(self.maximum_sleep_nanoseconds.get(), self.current_sleep_nanoseconds.get().saturating_mul(2));
		sleep(Duration::from_nanos(current_sleep_nanoseconds));
		self.current_sleep_nanoseconds = new_non_zero_u64(current_sleep_nanoseconds);
		true
	}
}
