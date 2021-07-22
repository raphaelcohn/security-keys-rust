// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// Back off settings.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct CardSharedAccessBackOff
{
	reset_retry_attempts: usize,
	
	remaining_reconnect_retry_attempts: usize,
	
	reconnect_maximum_sleep: Duration,
	
	reconnect_current_sleep: Duration,
}

impl Default for CardSharedAccessBackOff
{
	#[inline(always)]
	fn default() -> Self
	{
		Self::Default
	}
}

impl CardSharedAccessBackOff
{
	/// Default settings.
	pub const Default: Self = Self::new(3, 5, Duration::from_secs(1), Duration::from_millis(1));
	
	/// New instance.
	#[inline(always)]
	pub const fn new(reset_retry_attempts: usize, reconnect_retry_attempts: usize, reconnect_maximum_sleep: Duration, reconnect_initial_sleep: Duration) -> Self
	{
		Self
		{
			reset_retry_attempts,
			
			remaining_reconnect_retry_attempts: reconnect_retry_attempts,
			
			reconnect_maximum_sleep,
		
			reconnect_current_sleep: reconnect_initial_sleep,
		}
	}
	
	#[inline(always)]
	const fn remaining_reset_retry_attempts(&self) -> RemainingResetRetryAttempts
	{
		RemainingResetRetryAttempts(self.reset_retry_attempts)
	}
	
	#[inline(always)]
	fn reconnect_back_off_and_sleep(&mut self) -> Result<(), ConnectCardError>
	{
		self.remaining_reconnect_retry_attempts = match self.remaining_reconnect_retry_attempts.checked_sub(1)
		{
			None => return Err(ConnectCardError::GivingUpAsCanNotGetSharedAccess),
			
			Some(remaining_attempts) => remaining_attempts,
		};
		
		const DoubleSleepForEachRetry: u32 = 2;
		let current_sleep = max(self.reconnect_maximum_sleep, self.reconnect_current_sleep.saturating_mul(DoubleSleepForEachRetry));
		sleep(current_sleep);
		self.reconnect_current_sleep = current_sleep;
		Ok(())
	}
}
