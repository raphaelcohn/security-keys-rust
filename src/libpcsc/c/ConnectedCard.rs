// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct ConnectedCard
{
	handle: SCARDHANDLE,
	
	active_protocol: Protocol,
	
	is_direct: bool,
	
	is_shared: bool,
	
	card_shared_access_back_off: CardSharedAccessBackOff,
	
	reconnect_card_disposition: CardDisposition,
	
	disposed: bool,
}

impl Drop for ConnectedCard
{
	#[inline(always)]
	fn drop(&mut self)
	{
		assert!(self.disposed, "Card was not disconnected")
	}
}

impl ConnectedCard
{
	#[inline(always)]
	pub(crate) const fn active_protocol(&self) -> Protocol
	{
		self.active_protocol
	}
	
	/*
	SCardStatus()

    SCardStatus() returns a bit field on pcsc-lite but a enumeration on Windows.

    This difference may be resolved in a future version of pcsc-lite. The bit-fields would then only contain one bit set.

    You can have a portable code using:
    if (dwState & SCARD_PRESENT)
    {
      // card is present
    }

	 */
	
	// SCardTransmit()
	
	// SCardSetAttrib()
	
	// SCardGetAttrib()
	
	// SCardControl()
	
	/// Begins a transaction.
	pub(crate) fn begin_transaction(self) -> Result<TransactedCommandOutcome<ConnectedCardTransaction>, CardTransactionError>
	{
		if self.is_shared
		{
			self.begin_shared_transaction()
		}
		else
		{
			self.begun_transaction()
		}
	}
	
	#[inline(always)]
	pub(crate) fn disconnect(mut self, card_disposition: CardDisposition) -> Result<(), CardTransactionError>
	{
		self.disposed = true;
		
		let ConnectedCard { handle, .. } = self;
		
		let result = unsafe { SCardDisconnect(handle, card_disposition.into_DWORD()) };
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			Ok(())
		}
		else
		{
			use self::CardTransactionError::*;
			use self::CommunicationError::*;
			
			let error = match result
			{
				SCARD_E_NO_SMARTCARD => NoSmartCard,
				
				SCARD_E_READER_UNAVAILABLE => UnavailableCardReader,
				
				SCARD_E_NO_MEMORY => Communication(OutOfMemory),
				
				SCARD_E_NO_SERVICE => Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished),
				
				SCARD_F_COMM_ERROR => Communication(InternalCommunications),
				
				SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
				
				_ => unreachable!("Undocumented error {} from SCardConnect()", result),
			};
			Err(error)
		}
	}
	
	#[inline(always)]
	fn begin_shared_transaction(mut self) -> Result<TransactedCommandOutcome<ConnectedCardTransaction>, CardTransactionError>
	{
		debug_assert!(self.is_shared);
		
		let result = unsafe { SCardBeginTransaction(self.handle) };
		if likely!(result == SCARD_S_SUCCESS)
		{
			return self.begun_transaction()
		}
		
		use self::CardTransactionError::*;
		use self::CommunicationError::*;
		
		use self::TransactedCommandOutcome::*;
		
		let error = match result
		{
			SCARD_E_SHARING_VIOLATION => return Ok(SharingViolation(self)),
			
			SCARD_W_RESET_CARD if self.is_shared =>
			{
				self.reconnect()?;
				return Ok(TransactionInterrupted(self))
			}
			
			SCARD_E_NO_SMARTCARD => NoSmartCard,
			
			SCARD_E_READER_UNAVAILABLE => UnavailableCardReader,
			
			SCARD_E_NO_MEMORY => Communication(OutOfMemory),
			
			SCARD_E_NO_SERVICE => Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished),
			
			SCARD_F_COMM_ERROR => Communication(InternalCommunications),
			
			SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
			
			_ => unreachable!("Undocumented error {} from SCardConnect()", result),
		};
		
		Err(error)
	}
	
	#[inline(always)]
	fn begun_transaction(self) -> Result<TransactedCommandOutcome<ConnectedCardTransaction>, CardTransactionError>
	{
		Ok(TransactedCommandOutcome::Succeeded(ConnectedCardTransaction { connected_card: self, disposed: false }))
	}
	
	// libpcsclite: Any PC/SC transaction held by the process is still valid after SCardReconnect().
	// windows: PC/SC transactions are released and a new call to SCardBeginTransaction() must be done.
	#[inline(always)]
	fn reconnect(&mut self) -> Result<(), CardConnectError>
	{
		debug_assert_eq!(self.is_shared, true);
		let (share_mode, dwPreferredProtocols) = if unlikely!(self.is_direct)
		{
			(SCARD_SHARE_DIRECT, 0)
		}
		else
		{
			(SCARD_SHARE_SHARED, self.active_protocol.into_DWORD())
		};
		let mut active_protocol = MaybeUninit::uninit();
		let mut card_shared_access_back_off = self.card_shared_access_back_off.clone();
		
		loop
		{
			let result = unsafe { SCardReconnect(self.handle, share_mode, dwPreferredProtocols, self.reconnect_card_disposition.into_DWORD(), active_protocol.as_mut_ptr()) };
			if likely!(result == SCARD_S_SUCCESS)
			{
				break
			}
			else
			{
				use self::CommunicationError::*;
				use self::CardConnectError::*;
				let error = match result
				{
					SCARD_E_SHARING_VIOLATION => if card_shared_access_back_off.sleep()
					{
						continue
					}
					else
					{
						GivingUpAsCanNotGetSharedAccess
					},
					
					SCARD_E_NO_SMARTCARD => NoSmartCard,
					
					SCARD_E_UNSUPPORTED_FEATURE => PreferredProtocolsUnsupported,
					
					SCARD_E_READER_UNAVAILABLE => UnavailableCardReader,
					
					SCARD_W_UNPOWERED_CARD => CardIsUnpowered,
					
					SCARD_W_UNRESPONSIVE_CARD => CardIsMute,
					
					SCARD_W_REMOVED_CARD => CardRemoved,
					
					SCARD_E_NO_MEMORY => Communication(OutOfMemory),
					
					SCARD_E_NO_SERVICE => Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished),
					
					SCARD_F_COMM_ERROR => Communication(InternalCommunications),
					
					SCARD_F_INTERNAL_ERROR => panic!("Internal error"),
					
					SCARD_E_PROTO_MISMATCH => unimplemented!("Protocols are validated before being passed"),
					
					SCARD_E_INVALID_PARAMETER => unreachable!("phCard and pdwActiveProtocol are not null"),
					
					SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
					
					_ => unreachable!("Undocumented error {} from SCardReconnect()", result),
				};
				return Err(error)
			}
		}
		self.active_protocol = unsafe { transmute(active_protocol.assume_init()) };
		Ok(())
	}
}
