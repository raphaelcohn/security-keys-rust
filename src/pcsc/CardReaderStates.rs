// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[repr(transparent)]
pub(crate) struct CardReaderStates<'card_reader_names, UserData>(ArrayVec<SCARD_READERSTATE, PCSCLITE_MAX_READERS_CONTEXTS>, PhantomData<&'card_reader_names UserData>);

impl<'card_reader_names, UserData> Drop for CardReaderStates<'card_reader_names, UserData>
{
	#[inline(always)]
	fn drop(&mut self)
	{
		for reader_state in self.0.iter()
		{
			let user_data_raw_pointer = reader_state.pvUserData;
			if unlikely!(!user_data_raw_pointer.is_null())
			{
				unsafe { drop(Box::from_raw(user_data_raw_pointer)) };
			}
		}
	}
}

impl<'card_reader_names, UserData> CardReaderStates<'card_reader_names, UserData>
{
	#[inline(always)]
	pub(crate) const fn new() -> Self
	{
		Self(ArrayVec::new_const(), PhantomData)
	}
	
	#[inline(always)]
	pub(crate) fn length(&self) -> usize
	{
		self.0.len()
	}
	
	/// Note that if a reader state is ignored, then on return, if adjusted using `change_reader_state_notification()`, it will become `SCARD_STATE_UNAWARE`.
	#[inline(always)]
	pub(crate) fn push_reader_state(&mut self, card_reader_name: CardReaderEventName<'card_reader_names>, user_data: Option<Box<UserData>>, ignore: bool)
	{
		self.0.push
		(
			SCARD_READERSTATE
			{
				szReader: card_reader_name.raw_reader_name_or_special(),
				
				pvUserData: match user_data
				{
					None => null_mut(),
					
					Some(user_data) => Box::into_raw(user_data) as *mut c_void,
				},
				
				dwCurrentState: if unlikely!(ignore)
				{
					SCARD_STATE_IGNORE
				}
				else
				{
					SCARD_STATE_UNAWARE
				},
				
				dwEventState: SCARD_STATE_UNAWARE,
				
				cbAtr: 0,
				
				rgbAtr: unsafe_uninitialized(),
			}
		)
	}
	
	#[inline(always)]
	pub(crate) fn get_reader_state(&self, index: usize) -> (CardReaderEventName<'card_reader_names>, Option<&UserData>, InsertionsAndRemovalsCount, StateChanged, CardReaderState)
	{
		let reader_state = self.0.get_unchecked_safe(index);
		
		let reader_name = CardReaderEventName::recreate(reader_state.szReader);
		
		let user_data =
		{
			let user_data_raw_pointer = reader_state.pvUserData;
			if likely!(user_data_raw_pointer.is_null())
			{
				None
			}
			else
			{
				Some(unsafe { & * (user_data_raw_pointer as *const UserData) })
			}
		};
		
		let (insertions_and_removals_count, event_state) =
		{
			let event_state = reader_state.dwEventState as u32;
			(
				(event_state >> 16) as u16,
				(event_state & 0xFFFF) as u16,
			)
		};
		
		let (has_changed, reader_event_state) = Self::process_event_state(event_state, reader_state);
		
		(reader_name, user_data, insertions_and_removals_count, has_changed, reader_event_state)
	}
	
	#[inline(always)]
	pub(crate) fn change_reader_state_notification(&mut self, index: usize, change_reader_state_notification: ChangeCardReaderStateNotification)
	{
		let reader_state = self.0.get_unchecked_mut_safe(index);
		
		use self::ChangeCardReaderStateNotification::*;
		
		reader_state.dwCurrentState = match change_reader_state_notification
		{
			Unaware => SCARD_STATE_UNAWARE,
			
			Ignore => SCARD_STATE_IGNORE,
			
			Update => reader_state.dwEventState,
		};
	}
	
	#[inline(always)]
	fn get_status_change(&mut self, timeout: Timeout, context: SCARDCONTEXT) -> Result<(), CardReaderStatusChangeError>
	{
		let reader_states_length = self.0.len() as DWORD;
		
		let result = unsafe { SCardGetStatusChange(context, timeout.into_DWORD(), self.0.as_mut_ptr(), reader_states_length) };
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			return Ok(())
		}
		
		use self::CardReaderStatusChangeError::*;
		use self::UnavailableOrCommunicationError::*;
		use self::UnavailableError::*;
		use self::CommunicationError::*;
		let error = match result
		{
			SCARD_E_UNKNOWN_READER => UnknownCardReader,
			
			SCARD_E_CANCELLED => Cancelled,
			
			SCARD_E_TIMEOUT => TimedOut,
			
			SCARD_W_UNPOWERED_CARD => UnavailableOrCommunication(Unavailable(CardIsUnpowered)),
			
			SCARD_W_UNRESPONSIVE_CARD => UnavailableOrCommunication(Unavailable(CardIsMute)),
			
			SCARD_W_REMOVED_CARD => UnavailableOrCommunication(Unavailable(CardRemoved)),
			
			SCARD_E_NO_SMARTCARD => UnavailableOrCommunication(Unavailable(NoCard)),
			
			SCARD_E_READER_UNAVAILABLE => UnavailableOrCommunication(Unavailable(CardReaderUnavailable)),
			
			SCARD_E_NO_MEMORY => UnavailableOrCommunication(Communication(OutOfMemory)),
			
			SCARD_E_NO_SERVICE => UnavailableOrCommunication(Communication(ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished)),
			
			SCARD_F_COMM_ERROR => UnavailableOrCommunication(Communication(InternalCommunications)),
			
			SCARD_F_INTERNAL_ERROR => panic!("Internal error"),
			
			SCARD_E_INVALID_PARAMETER => unreachable!("Null reader states and non-zero reader_states_length, or more reader_states than PCSCLITE_MAX_READERS_CONTEXTS"),
			
			SCARD_E_INVALID_VALUE => unreachable!("Empty reader name"),
			
			SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
			
			_ => unreachable!("Unknown error {}", result),
		};
		Err(error)
	}
	
	#[inline(always)]
	fn process_event_state(event_state: u16, reader_state: &SCARD_READERSTATE) -> (StateChanged, CardReaderState)
	{
		#[inline(always)]
		const fn has_bit_set(event_state: DWORD, bit: DWORD) -> bool
		{
			(event_state & bit) != 0
		}
		
		let event_state = event_state as DWORD;
		
		use self::CardReaderState::*;
		
		// Will be 0 (SCARD_STATE_UNAWARE) if dwCurrentState was SCARD_STATE_IGNORE, as dwEventState is reset to 0 on entry.
		if event_state == 0
		{
			return (false, Ignored)
		}
		
		let has_changed = has_bit_set(event_state, SCARD_STATE_CHANGED);
		
		let is_unavailable = has_bit_set(event_state , SCARD_STATE_UNAVAILABLE);
		if is_unavailable
		{
			// This is true for a reader name not known in the reader states once the wait loop has been entered; if the wait loop is not entered, SCARD_E_UNKNOWN_READER is returned instead.
			let is_unknown = has_bit_set(event_state , SCARD_STATE_UNKNOWN);
			let reader_state = if is_unknown
			{
				Unknown
			}
			else
			{
				Unavailable
			};
			
			return (has_changed, reader_state)
		}
		
		let is_empty = has_bit_set(event_state , SCARD_STATE_EMPTY);
		if is_empty
		{
			return (has_changed, Empty)
		}
		
		let is_present = has_bit_set(event_state, SCARD_STATE_PRESENT);
		if is_present
		{
			use self::PresentExclusivity::*;
			let is_exclusive = has_bit_set(event_state, SCARD_STATE_EXCLUSIVE);
			let is_in_use = has_bit_set(event_state, SCARD_STATE_INUSE);
			let exclusivity = match (is_exclusive, is_in_use)
			{
				(true, false) => Exclusive,
				
				(false, true) => Last,
				
				(false, false) => Shared,
				
				(true, true) => unreachable!("A reader should not be both exclusive and in-use"),
			};
			
			let is_mute = has_bit_set(event_state, SCARD_STATE_MUTE);
			
			let answer_to_reset = AnswerToReset(reader_state.rgbAtr.get_unchecked_range_safe(0..reader_state.cbAtr));
			return (has_changed, Present { exclusivity, is_mute, answer_to_reset })
		}
		
		panic!("Unknown combination of states {}", event_state)
	}
}
