// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct Context(Rc<ContextInner>);

impl Context
{
	/// Affected by the environment variable `PCSCLITE_NO_BLOCKING`.
	#[inline(always)]
	fn establish(scope: Scope) -> Result<Self, ContextEstablishmentError>
	{
		let mut context_handle = MaybeUninit::uninit();
		
		let result = unsafe { SCardEstablishContext(scope.into_DWORD(), null(), null(), context_handle.as_mut_ptr()) };
		
		if likely!(result == SCARD_S_SUCCESS)
		{
			let handle = unsafe { context_handle.assume_init() };
			Ok(Self(Rc::new(handle)))
		}
		else
		{
			use self::ContextEstablishmentError::*;
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
	
	#[inline(always)]
	fn list_all_connected_card_readers<'buffer>(&self, buffer_provider: &'buffer mut impl BufferProvider) -> Result<ReaderNames<'buffer>, ()>
	{
		static NoReadersAvailable: &'static [u8] = b"\0";
		
		loop
		{
			let mut readers_buffer_length = MaybeUninit::uninit();
			let result = unsafe { SCardListReaders(self.get_context(), null(), null_mut(), readers_buffer_length.as_mut_ptr()) };
			
			if unlikely!(result != SCARD_S_SUCCESS)
			{
				return match result
				{
					SCARD_E_NO_READERS_AVAILABLE => Ok(ReaderNames(NoReadersAvailable)),
					
					SCARD_E_NO_MEMORY => Err(()),
					
					SCARD_E_NO_SERVICE => Err(()),
					
					SCARD_E_INSUFFICIENT_BUFFER => unreachable!("SCARD_E_INSUFFICIENT_BUFFER should not happen as mszReaders was null"),
					
					SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
					
					SCARD_E_INVALID_PARAMETER => unreachable!("pcchReaders should not happen as pcchReaders was not null"),
					
					_ => unreachable!("Undocumented error {} from SCardListReaders()", result),
				}
			}
			
			let mut readers_buffer_length = unsafe { readers_buffer_length.assume_init() };
			let readers_buffer: &mut [c_char] = buffer_provider.provide_buffer(readers_buffer_length as usize);
			
			let result = unsafe { SCardListReaders(self.get_context(), null(), readers_buffer.as_mut_ptr(), &mut readers_buffer_length) };
			
			if likely!(result == SCARD_S_SUCCESS)
			{
				// readers_buffer_length can actually be shorter.
				let readers_buffer = readers_buffer.get_unchecked_range_safe(0 .. (readers_buffer_length as usize));
				return Ok(readers_buffer)
			}
			
			match result
			{
				SCARD_E_NO_READERS_AVAILABLE => return Ok(ReaderNames(NoReadersAvailable)),
				
				SCARD_E_NO_MEMORY => return Err(()),
				
				SCARD_E_NO_SERVICE => return Err(()),
				
				SCARD_E_INSUFFICIENT_BUFFER => continue,
				
				SCARD_E_INVALID_HANDLE => unreachable!("Invalid context handle"),
				
				SCARD_E_INVALID_PARAMETER => unreachable!("pcchReaders should not happen as pcchReaders was not null"),
				
				_ => unreachable!("Undocumented error {} from SCardListReaders()", result),
			}
		}
	}
	
	#[inline(always)]
	fn connect_card(&self)
	{
		SCardConnect()
	}
	
	// Has an extra special reader name.
	#[inline(always)]
	fn block_getting_status_change(&self, timeout: Timeout, reader_states: &mut ReaderStates) -> Result<(), ()>
	{
		#[repr(transparent)]
		struct ReaderStates<UserData>(ArrayVec<SCARD_READERSTATE, PCSCLITE_MAX_READERS_CONTEXTS>, PhantomData<UserData>);
		
		impl<UserData> Drop for ReaderStates<UserData>
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
		
		impl<UserData> ReaderStates<UserData>
		{
			#[inline(always)]
			fn special_reader_name_for_detecting_card_reader_insertions_and_removals() -> *const c_char
			{
				static PNP_NOTIFICATION: &'static [u8] = b"\\\\?PnP?\\Notification\0";
				PNP_NOTIFICATION.as_ptr() as *const c_char
			}
			
			#[inline(always)]
			const fn new() -> Self
			{
				Self(ArrayVec::new_const())
			}
			
			#[inline(always)]
			fn is_empty(&self) -> bool
			{
				self.0.is_empty()
			}
			
			/// 128 characters ?including \0.
			#[inline(always)]
			fn push_reader_state<'reader_name: 'self, 'self>(&'self mut self, reader_name: Option<&'reader_name CStr>, user_data: Option<Box<UserData>>, known_state: KnownState)
			{
				self.0.push
				(
					SCARD_READERSTATE
					{
						szReader: match reader_name
						{
							None => SpecialPnpName,
							
							// TODO: CStr management.
							Some(reader_name) => CStr,
						},
						
						pvUserData: match user_data
						{
							None => null_mut(),
							
							Some(user_data) => Box::into_raw(user_data),
						},
						
						dwCurrentState: known_state.into_DWORD(),
						
						dwEventState: unsafe { uninitialized() },
						
						cbAtr: 0,
						rgbAtr: []
					}
				)
			}
			
			// dwEventState will be forced to zero on entry.
			/*
dwEventState also contains a number of events in the upper 16 bits
dwEventState & 0xFFFF0000). This number of events is incremented
for each card insertion or removal in the specified reader. This can
be used to detect a card removal/insertion between two calls to
SCardGetStatusChange()

dwCurrentState should be set, on entry to blocking functionality, to dwEventState to detect any changes.
			 */
			#[inline(always)]
			fn get_reader_state<'reader_name: 'self, 'self>(&'self self, index: usize) -> (&'reader_name CStr, Option<&'self UserData>, u16, u16, &'self [u8])
			{
				let reader_state = self.0.get_unchecked_safe(index);
				
				// Only valid if readerState & SCARD_PRESENT (can check by inspecting value of cbAtr)
				let answer_to_reset = reader_state.rgbAtr.get_unchecked_range_safe(0 .. reader_state.cbAtr);
				
				let user_data_raw_pointer = reader_state.pvUserData;
				let user_data = if likely!(user_data_raw_pointer.is_null())
				{
					None
				}
				else
				{
					Some(unsafe { & * user_data_raw_pointer })
				};
				
				let event_state = reader_state.dwEventState as u32;
				let insertion_and_removal_count = (event_state >> 16) as u16;
				let current_state = (event_state & 0xFFFF) as u16;
				
				let raw_reader_name_or_special = reader_state.szReader;
				let reader_name = if raw_reader_name_or_special == Self::special_reader_name_for_detecting_card_reader_insertions_and_removals()
				{
					x
				}
				else
				{
					unsafe { CStr::from_ptr(raw_reader_name_or_special) }
				};
				
				(reader_name, user_data, insertion_and_removal_count, current_state, answer_to_reset)
			}
		}
		
		if unlikely!(reader_states.is_empty())
		{
			return Ok(())
		}
		
		
		
		let reader_states_length = reader_states.len() as DWORD;
		
		/*
			Valid 'input' states
				SCARD_STATE_UNAWARE
				SCARD_STATE_IGNORE
				
				SCARD_STATE_UNAVAILABLE
			
			Valid 'output' states
				SCARD_STATE_CHANGED | ???
				SCARD_STATE_UNKNOWN | SCARD_STATE_CHANGED | SCARD_STATE_IGNORE
				SCARD_STATE_UNAVAILABLE
				SCARD_STATE_EMPTY
				SCARD_STATE_PRESENT
				SCARD_STATE_PRESENT | SCARD_STATE_EXCLUSIVE
				SCARD_STATE_PRESENT | SCARD_STATE_INUSE
				SCARD_STATE_MUTE
				
				?SCARD_STATE_UNPOWERED
				?STATE_ATRMATCH
				
			
		 */
		
		unsafe { SCardGetStatusChange(self.get_context(), timeout.into_DWORD(), reader_states.as_mut_ptr(), reader_states_length) };
	}
	
	/// Cancels a blocking `block_getting_status_change()`.
	///
	/// In practice, will require a separate thread.
	#[inline(always)]
	fn cancel_block_getting_status_change(&self) -> bool
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
	fn get_context(self) -> SCARDCONTEXT
	{
		(self.0).0
	}
}

