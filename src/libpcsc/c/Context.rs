// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct Context(Rc<ContextInner>);

impl Context
{
	/// Affected by the environment variable `PCSCLITE_NO_BLOCKING`.
	#[inline(always)]
	pub(crate) fn establish(scope: Scope) -> Result<Self, CommunicationError>
	{
		let mut context_handle = MaybeUninit::uninit();
		
		let result = unsafe { SCardEstablishContext(scope.into_DWORD(), null(), null(), context_handle.as_mut_ptr()) };
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			let handle = unsafe { context_handle.assume_init() };
			Ok(Self(Rc::new(ContextInner(handle))))
		}
		else
		{
			use self::CommunicationError::*;
			match result
			{
				SCARD_E_NO_MEMORY => Err(OutOfMemory),
				SCARD_E_NO_SERVICE => Err(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished),
				SCARD_F_COMM_ERROR => Err(InternalCommunications),
				
				SCARD_E_INVALID_PARAMETER => unreachable!("phContext is null"),
				SCARD_E_INVALID_VALUE => unreachable!("scope is invalid"),
				SCARD_F_INTERNAL_ERROR => unreachable!("An internal consistency check failed"),
				
				_ => unreachable!("Undocumented error {} from SCardEstablishContext()", result),
			}
		}
	}
	
	/// This uses PThread mutexes; avoid.
	#[inline(always)]
	pub(crate) fn is_valid(&self) -> bool
	{
		let result = unsafe { SCardIsValidContext(self.get_context()) };
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			true
		}
		else
		{
			match result
			{
				SCARD_E_INVALID_HANDLE => false,
				
				_ => unreachable!("Undocumented error {} from SCardIsValidContext()", result),
			}
		}
	}
	
	#[inline(always)]
	pub(crate) fn initial_card_reader_states(&self, buffer_provider: &Rc<BufferProvider>, mut card_reader_state_user: impl for<'callback> FnMut(CardReaderEventName<'callback>, InsertionsAndRemovalsCount, CardReaderState<'callback>) -> ()) -> Result<(), CardReaderStatusChangeError>
	{
		let card_reader_names = self.iterator_over_all_connected_card_readers(buffer_provider).map_err(CardReaderStatusChangeError::Communication)?;
		let mut card_reader_states = card_reader_names.create_card_reader_states();
		self.update_card_reader_states(Timeout::Immediate, &mut card_reader_states)?;
		
		for index in 0 .. card_reader_states.length()
		{
			let (card_reader_event_name, _user_data, insertions_and_removals_count, _state_changed, card_reader_state) = card_reader_states.get_reader_state(index);
			card_reader_state_user(card_reader_event_name, insertions_and_removals_count, card_reader_state)
		}
		
		Ok(())
	}
	
	#[inline(always)]
	pub(crate) fn iterator_over_all_connected_card_readers(&self, buffer_provider: &Rc<BufferProvider>) -> Result<CardReaderNames, CommunicationError>
	{
		loop
		{
			let mut readers_buffer_length = MaybeUninit::uninit();
			let result = unsafe { SCardListReaders(self.get_context(), null(), null_mut(), readers_buffer_length.as_mut_ptr()) };
			
			use self::CommunicationError::*;
			
			if unlikely!(result != SCARD_S_SUCCESS)
			{
				return match result
				{
					SCARD_E_NO_READERS_AVAILABLE => Ok(CardReaderNames::Empty),
					
					SCARD_E_NO_MEMORY => Err(OutOfMemory),
					
					SCARD_E_NO_SERVICE => Err(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished),
					
					SCARD_F_COMM_ERROR => Err(InternalCommunications),
					
					SCARD_E_INSUFFICIENT_BUFFER => unreachable!("SCARD_E_INSUFFICIENT_BUFFER should not happen as mszReaders was null"),
					
					SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
					
					SCARD_E_INVALID_PARAMETER => unreachable!("pcchReaders should not happen as pcchReaders was not null"),
					
					_ => unreachable!("Undocumented error {} from SCardListReaders()", result),
				}
			}
			
			let mut readers_buffer_length = unsafe { readers_buffer_length.assume_init() };
			let mut readers_buffer = buffer_provider.provide_buffer(readers_buffer_length as usize).map_err(|_| OutOfMemory)?;
			
			let result = unsafe { SCardListReaders(self.get_context(), null(), readers_buffer.c_string_pointer_mut(), &mut readers_buffer_length) };
			
			if likely!(result == SCARD_S_SUCCESS)
			{
				readers_buffer.shorten(readers_buffer_length);
				return Ok(CardReaderNames::new(readers_buffer))
			}
			
			return match result
			{
				SCARD_E_NO_READERS_AVAILABLE => Ok(CardReaderNames::Empty),
				
				SCARD_E_NO_MEMORY => Err(OutOfMemory),
				
				SCARD_E_NO_SERVICE => Err(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished),
				
				SCARD_F_COMM_ERROR => Err(InternalCommunications),
				
				SCARD_E_INSUFFICIENT_BUFFER => continue,
				
				SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
				
				SCARD_E_INVALID_PARAMETER => unreachable!("Should not happen as pcchReaders was not null"),
				
				_ => unreachable!("Undocumented error {} from SCardListReaders()", result),
			}
		}
	}
	
	#[inline(always)]
	pub(crate) fn update_card_reader_states<UserData>(&self, timeout: Timeout, card_reader_states: &mut CardReaderStates<UserData>) -> Result<(), CardReaderStatusChangeError>
	{
		card_reader_states.get_status_change(timeout, self.get_context())
	}
	
	/// Cancels a blocking `update_card_reader_states()`.
	///
	/// In practice, will require a separate thread.
	#[inline(always)]
	pub(crate) fn cancel_update_card_reader_states(&self) -> bool
	{
		let result = unsafe { SCardCancel(self.get_context()) };
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			true
		}
		else
		{
			match result
			{
				SCARD_E_NO_SERVICE => false,
				
				SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
				
				_ => unreachable!("Undocumented error {} from SCardCancel()", result),
			}
		}
	}
	
	#[inline(always)]
	pub(crate) fn connect_card(&self, card_shared_access_back_off: CardSharedAccessBackOff, reconnect_card_disposition: CardDisposition, card_reader_name: CardReaderName, share_mode_and_preferred_protocols: ShareModeAndPreferredProtocols) -> Result<ConnectedCard, CardConnectError>
	{
		let (dwShareMode, dwPreferredProtocols, is_direct, is_shared) = share_mode_and_preferred_protocols.into_DWORDs();
		let mut handle = MaybeUninit::uninit();
		let mut active_protocol = MaybeUninit::uninit();
		
		let mut card_shared_access_back_off_for_connect = card_shared_access_back_off.clone();
		loop
		{
			let result = unsafe { SCardConnect(self.get_context(), card_reader_name.as_ptr(), dwShareMode, dwPreferredProtocols, handle.as_mut_ptr(), active_protocol.as_mut_ptr()) };
			
			if likely!(result == SCARD_S_SUCCESS)
			{
				break
			}
			
			use self::CardConnectError::*;
			use self::CommunicationError::*;
			
			let error = match result
			{
				SCARD_E_SHARING_VIOLATION => if card_shared_access_back_off_for_connect.sleep()
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
				
				SCARD_E_NO_MEMORY => Communication(OutOfMemory),
				
				SCARD_E_NO_SERVICE => Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished),
				
				SCARD_F_COMM_ERROR => Communication(InternalCommunications),
				
				SCARD_E_PROTO_MISMATCH => unimplemented!("Protocols are validated before being passed"),
				
				SCARD_E_INVALID_PARAMETER => unreachable!("phCard and pdwActiveProtocol are not null"),
				
				SCARD_E_UNKNOWN_READER => unreachable!("card_reader_name is not null"),
				
				SCARD_E_INVALID_VALUE => unreachable!("card_reader_name can not exceed maximum, or used an invalid share mode"),
				
				SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
				
				_ => unreachable!("Undocumented error {} from SCardConnect()", result),
			};
			return Err(error)
		}
		
		Ok
		(
			ConnectedCard
			{
				handle: unsafe { handle.assume_init() },
			
				active_protocol: unsafe { transmute(active_protocol.assume_init()) },
				
				is_direct,
				
				is_shared,
				
				card_shared_access_back_off,
				
				reconnect_card_disposition,
				
				disposed: false
			}
		)
	}
	
	#[inline(always)]
	fn get_context(&self) -> SCARDCONTEXT
	{
		(self.0).0
	}
}

