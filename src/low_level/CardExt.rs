// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(super) trait CardExt: CardOrTransactionExt
{
	fn start_transaction<Callback: FnOnce(Transaction) -> Result<R, CardError>, R>(&mut self, callback: Callback) -> Result<R, CardError>;
}

impl CardExt for Card
{
	#[inline(always)]
	fn start_transaction<Callback: FnOnce(Transaction) -> Result<R, CardError>, R>(&mut self, callback: Callback) -> Result<R, CardError>
	{
		let transaction = self.transaction().map_err(CardError::StartTransaction)?;
		callback(transaction)
	}
}
