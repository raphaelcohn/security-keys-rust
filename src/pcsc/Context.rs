// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A PC/SC lite context.
///
/// Only one per thread is needed.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Context(Rc<ContextInner>);

/// Hack as Rust does not like const generics with namespaces.
pub const MaximumAttributeValueSize: usize = Context::MaximumAttributeValueSize;

impl Context
{
	/// Maximum buffer size.
	pub const MaximumSendOrReceiveBufferSize: usize = MAX_BUFFER_SIZE;
	
	/// Maximum extended buffer size.
	pub const MaximumExtendedSendOrReceiveBufferSize: usize = MAX_BUFFER_SIZE_EXTENDED;
	
	/// Maximum attribute size.
	pub const MaximumAttributeValueSize: usize = Self::MaximumSendOrReceiveBufferSize;
	
	/// High-level API.
	#[inline(always)]
	pub fn establish_activity(scope: Scope) -> Result<Self, ActivityError>
	{
		Self::establish(scope).map_err(|cause| ActivityError::EstablishContext { cause, scope })
	}
	
	/// Affected by the environment variable `PCSCLITE_NO_BLOCKING`.
	pub fn establish(scope: Scope) -> Result<Self, CommunicationError>
	{
		let mut context_handle = MaybeUninit::uninit();
		
		let result = unsafe { SCardEstablishContext(scope.into_DWORD(), null(), null(), context_handle.as_mut_ptr()) };
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			let handle = unsafe { context_handle.assume_init() };
			return Ok(Self(Rc::new(ContextInner(handle))))
		}
		
		use self::CommunicationError::*;
		let error = match result
		{
			SCARD_E_NO_MEMORY => OutOfMemory,
			
			SCARD_E_NO_SERVICE => ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished,
			
			SCARD_F_COMM_ERROR => InternalCommunications,
			
			SCARD_F_INTERNAL_ERROR => InternalError,
			
			SCARD_E_INVALID_PARAMETER => unreachable!("phContext is null"),
			
			SCARD_E_INVALID_VALUE => unreachable!("scope is invalid"),
			
			_ => unreachable!("Undocumented error {} from SCardEstablishContext()", result),
		};
		Err(error)
	}
	
	/// This uses PThread mutexes; avoid.
	#[allow(dead_code)]
	#[inline(always)]
	fn is_valid(&self) -> bool
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
	
	/// High-level API.
	#[inline(always)]
	pub fn initial_card_reader_states_activity(&self, card_reader_state_user: impl for<'callback> FnMut(CardReaderName<'callback>, InsertionsAndRemovalsCount, CardReaderState<'callback>) -> ()) -> Result<(), ActivityError>
	{
		self.initial_card_reader_states(card_reader_state_user).map_err(ActivityError::InitialCardReaderStates)
	}
	
	/// Mid-level API.
	#[inline(always)]
	pub fn initial_card_reader_states(&self, mut card_reader_state_user: impl for<'callback> FnMut(CardReaderName<'callback>, InsertionsAndRemovalsCount, CardReaderState<'callback>) -> ()) -> Result<(), CardReaderStatusChangeError>
	{
		let card_reader_names = self.connected_card_readers()?;
		let mut card_reader_states = card_reader_names.create_card_reader_states();
		self.update_card_reader_states(Timeout::Immediate, &mut card_reader_states)?;
		
		for index in 0 .. card_reader_states.length()
		{
			let (card_reader_event_name, _user_data, insertions_and_removals_count, _state_changed, card_reader_state) = card_reader_states.get_reader_state(index);
			card_reader_state_user(card_reader_event_name.state_change(), insertions_and_removals_count, card_reader_state)
		}
		
		Ok(())
	}
	
	/// High-level API.
	#[inline(always)]
	pub fn connected_card_readers_activity(&self) -> Result<CardReaderNames, ActivityError>
	{
		self.connected_card_readers().map_err(ActivityError::ConnectedCardReaders)
	}
	
	/// Low-level API.
	pub fn connected_card_readers(&self) -> Result<CardReaderNames, CommunicationError>
	{
		let mut reader_names = CardReaderNamesBuffer::new_const();
		
		let mut reader_names_length = reader_names.capacity() as DWORD;
		let result = unsafe { SCardListReaders(self.get_context(), null(), reader_names.as_mut_ptr() as *mut c_char, &mut reader_names_length) };
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			return Ok(CardReaderNames::from_valid_buffer(reader_names, reader_names_length))
		}
		
		use self::CommunicationError::*;
		
		let error = match result
		{
			SCARD_E_NO_READERS_AVAILABLE => return Ok(CardReaderNames::from_empty_buffer(reader_names)),
			
			SCARD_E_NO_MEMORY => OutOfMemory,
			
			SCARD_E_NO_SERVICE => ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished,
			
			SCARD_F_COMM_ERROR => InternalCommunications,
			
			SCARD_F_INTERNAL_ERROR => InternalError,
			
			SCARD_E_INSUFFICIENT_BUFFER => unreachable!("Supplied maximum buffer size"),
			
			SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
			
			SCARD_E_INVALID_PARAMETER => unreachable!("Should not happen as pcchReaders was not null"),
			
			_ => unreachable!("Undocumented error {} from SCardListReaders()", result),
		};
		return Err(error)
	}
	
	/// High-level API.
	#[inline(always)]
	pub fn update_card_reader_states_activity<UserData>(&self, timeout: Timeout, card_reader_states: &mut CardReaderStates<UserData>) -> Result<(), ActivityError>
	{
		self.update_card_reader_states(timeout, card_reader_states).map_err(ActivityError::UpdateCardReaderStates)
	}
	
	/// Low-level API.
	#[inline(always)]
	pub fn update_card_reader_states<UserData>(&self, timeout: Timeout, card_reader_states: &mut CardReaderStates<UserData>) -> Result<(), CardReaderStatusChangeError>
	{
		card_reader_states.get_status_change(timeout, self.get_context())
	}
	
	/// Cancels a blocking `update_card_reader_states()`.
	///
	/// In practice, will require a separate thread.
	#[allow(dead_code)]
	#[inline(always)]
	fn cancel_update_card_reader_states(&self) -> Result<bool, CommunicationError>
	{
		let result = unsafe { SCardCancel(self.get_context()) };
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			Ok(true)
		}
		else
		{
			match result
			{
				SCARD_E_NO_SERVICE => Ok(false),
				
				SCARD_F_INTERNAL_ERROR => Err(CommunicationError::InternalError),
				
				SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
				
				_ => unreachable!("Undocumented error {} from SCardCancel()", result),
			}
		}
	}
	
	/// High-level API.
	#[inline(always)]
	pub fn connect_card_activity(&self, card_shared_access_back_off: CardSharedAccessBackOff, reconnect_card_disposition: CardDisposition, card_reader_name: &CardReaderName, share_mode_and_preferred_protocols: ShareModeAndPreferredProtocols) -> Result<ConnectedCard, ActivityError>
	{
		self.connect_card(card_shared_access_back_off, reconnect_card_disposition, card_reader_name, share_mode_and_preferred_protocols).map_err(ActivityError::ConnectCard)
	}
	
	/// Mid-level API.
	pub fn connect_card(&self, card_shared_access_back_off: CardSharedAccessBackOff, reconnect_card_disposition: CardDisposition, card_reader_name: &CardReaderName, share_mode_and_preferred_protocols: ShareModeAndPreferredProtocols) -> Result<ConnectedCard, ConnectCardError>
	{
		let context = self.get_context();
		let card_reader_name_pointer = card_reader_name.as_ptr();
		let (dwShareMode, dwPreferredProtocols, is_direct, is_shared) = share_mode_and_preferred_protocols.into_DWORDs();
		let mut handle = MaybeUninit::uninit();
		let handle_pointer = handle.as_mut_ptr();
		let mut active_protocol = MaybeUninit::uninit();
		let active_protocol_pointer = active_protocol.as_mut_ptr();
		
		let mut card_shared_access_back_off_for_connect = card_shared_access_back_off.clone();
		loop
		{
			let result = unsafe { SCardConnect(context, card_reader_name_pointer, dwShareMode, dwPreferredProtocols, handle_pointer, active_protocol_pointer) };
			
			if likely!(result == SCARD_S_SUCCESS)
			{
				break
			}
			
			use self::ConnectCardError::*;
			use self::CommunicationError::*;
			use self::UnavailableError::*;
			use self::UnavailableOrCommunicationError::*;
			
			let error = match result
			{
				SCARD_E_SHARING_VIOLATION =>
				{
					card_shared_access_back_off_for_connect.reconnect_back_off_and_sleep()?;
					continue
				}
				
				SCARD_E_UNSUPPORTED_FEATURE => PreferredProtocolsUnsupported,
				
				SCARD_W_UNPOWERED_CARD => UnavailableOrCommunication(Unavailable(CardIsUnpowered)),
				
				SCARD_W_UNRESPONSIVE_CARD => UnavailableOrCommunication(Unavailable(CardIsMute)),
				
				SCARD_W_REMOVED_CARD => unreachable!("Should not be possible to have a removed card error in SCardConnect()"),
				
				SCARD_E_NO_SMARTCARD => UnavailableOrCommunication(Unavailable(NoCard)),
				
				SCARD_E_READER_UNAVAILABLE => UnavailableOrCommunication(Unavailable(CardReaderUnavailable)),
				
				SCARD_E_NO_MEMORY => UnavailableOrCommunication(Communication(OutOfMemory)),
				
				SCARD_E_NO_SERVICE => UnavailableOrCommunication(Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished)),
				
				SCARD_F_COMM_ERROR => UnavailableOrCommunication(Communication(InternalCommunications)),
				
				SCARD_F_INTERNAL_ERROR => UnavailableOrCommunication(Communication(InternalError)),
				
				SCARD_E_PROTO_MISMATCH => unreachable!("Protocols are validated before being passed"),
				
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
			
				active_protocol: Cell::new
				(
					if unlikely!(is_direct)
					{
						None
					}
					else
					{
						Some(unsafe { transmute(active_protocol.assume_init()) })
					}
				),
				
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
