// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct RemainingResetRetryAttempts(usize);

impl RemainingResetRetryAttempts
{
	#[inline(always)]
	fn card_was_reset<E: error::Error + From<ConnectCardError> + From<CardStatusError>>(&mut self, connected_card: &ConnectedCard) -> Result<(), E>
	{
		let remaining_retry_attempts = self.0;
		if unlikely!(remaining_retry_attempts == 0)
		{
			return Err(E::from(CardStatusError::TooManyResets))
		}
		self.0 = remaining_retry_attempts - 1;
		
		connected_card.reconnect()?;
		
		Ok(())
	}
}
