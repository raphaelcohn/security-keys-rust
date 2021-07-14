// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(crate) struct ConnectedCardTransaction
{
	connected_card: ConnectedCard,
	
	disposed: bool,
}

impl Drop for ConnectedCardTransaction
{
	#[inline(always)]
	fn drop(&mut self)
	{
		assert!(self.disposed, "Transaction was not ended")
	}
}

impl ConnectedCardTransaction
{
	#[inline(always)]
	pub(crate) fn end(mut self, end_transaction_disposition: CardDisposition) -> Result<TransactedCommandOutcome<()>, CardTransactionError>
	{
		self.disposed = true;
		let mut connected_card = unsafe { read(&self.connected_card) };
		drop(self);
		
		use self::TransactedCommandOutcome::*;
		
		let card_disposition = if connected_card.is_shared
		{
			let result = unsafe { SCardEndTransaction(connected_card.handle, end_transaction_disposition.into_DWORD()) };
			
			if likely!(result == SCARD_S_SUCCESS)
			{
				CardDisposition::Leave
			}
			else
			{
				use self::CardTransactionError::*;
				use self::CommunicationError::*;
				
				let error = match result
				{
					SCARD_E_SHARING_VIOLATION => return Ok(SharingViolation(connected_card)),
					
					// https://docs.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardendtransaction
					SCARD_W_RESET_CARD if connected_card.is_shared =>
					{
						connected_card.reconnect()?;
						
						return Ok(TransactionInterrupted(connected_card))
					},
					
					SCARD_E_NO_SMARTCARD => NoSmartCard,
					
					SCARD_E_READER_UNAVAILABLE => UnavailableCardReader,
					
					SCARD_E_NO_MEMORY => Communication(OutOfMemory),
					
					SCARD_E_NO_SERVICE => Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished),
					
					SCARD_F_COMM_ERROR => Communication(InternalCommunications),
					
					SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
					
					_ => unreachable!("Undocumented error {} from SCardEndTransaction()", result),
				};
				
				return Err(error)
			}
		}
		else
		{
			end_transaction_disposition
		};
		Ok(Succeeded(connected_card.disconnect(card_disposition)?))
	}
}
