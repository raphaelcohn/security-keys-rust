// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(super) trait CardOrTransactionExt: Sized
{
	#[inline(always)]
	fn get_status<Callback: for<'names_buf, 'atr_buf> FnOnce(ReaderNames<'names_buf>, Option<Protocol>, AnswerToReset<'atr_buf>) -> R, R>(&self, callback: Callback) -> Result<R, CardError>
	{
		use self::CardError::*;
		
		// names_length must be `<= u32::MAX as usize`.
		// answer_to_reset_length should always be `<= MAX_ATR_SIZE`.
		let (names_length, answer_to_reset_length) = self._status2_len_wrapper().map_err(StatusLength)?;
		let mut reader_names_buffer = Vec::new_buffer(names_length)?;
		let mut answer_to_reset_buffer = Vec::new_buffer(answer_to_reset_length)?;
		let card_status = self._status2_wrapper(&mut reader_names_buffer, &mut answer_to_reset_buffer).map_err(GetStatus)?;
		Ok(callback(card_status.reader_names(), card_status.protocol2(), AnswerToReset(card_status.atr())))
	}
	
	#[doc(hidden)]
	fn _status2_len_wrapper(&self) -> Result<(usize, usize), pcsc::Error>;
	
	#[doc(hidden)]
	fn _status2_wrapper<'names_buf, 'atr_buf>(&self, reader_names_buffer: &'names_buf mut [u8], answer_to_reset_buffer: &'atr_buf mut [u8]) -> Result<CardStatus<'names_buf, 'atr_buf>, pcsc::Error>;
	
	fn get_attribute_value<Callback: FnOnce(&[u8]) -> R, R>(&self, attribute: Attribute, callback: Callback) -> Result<R, CardError>;
	
	fn set_attribute_value(&self, attribute: Attribute, attribute_data: &[u8]) -> Result<(), CardError>;
	
	fn send_command(&self, command: ApplicationProtocolDataUnitCommand, response_length_encoding: ResponseLengthEncoding, send_buffer: &mut SendBuffer, receive_buffers: &mut ReceiveBuffers, response: &mut Response, command_chaining: CommandChaining) -> Result<(), CardError>
	{
		let mut result = command_chaining.send_command(self, command, response_length_encoding, send_buffer, receive_buffers, response)?;
		while result
		{
			result = self._send_single_command(ApplicationProtocolDataUnitCommand::GetResponse, response_length_encoding, send_buffer, receive_buffers, |response_data, response_code| response.process_response(response_data, response_code))??;
		}
		
		Ok(())
	}
	
	/// To use this, a smart card needs to support an extended capability called chaining.
	/// To use a `response_length_encoding` of `Long`, the card needs to support extended length for Lc and Le.
	/// If the `chunk_size` is greater than 255 bytes, `response_length_encoding` is forced to `Long` if there is any data to send; it assumed that a card reporting a `chunk_size` greater than 255 bytes supported an extended length for Lc and Le.
	fn _send_chained_command(&self, command: ApplicationProtocolDataUnitCommand, response_length_encoding: ResponseLengthEncoding, send_buffer: &mut SendBuffer, receive_buffers: &mut ReceiveBuffers, response: &mut Response, chunk_size: NonZeroU16) -> Result<bool, CardError>
	{
		use self::ResponseLengthEncoding::*;
		let response_length_encoding = match (response_length_encoding, chunk_size.get() > 255)
		{
			(None, _) => None,
			
			(_, true) => Long,
			
			_ => response_length_encoding,
		};
		
		let number_of_chunks = command.number_of_chunks(chunk_size).get();
		let final_chunk_index = number_of_chunks - 1;
		for chunk_index in 0 ..final_chunk_index
		{
			let chunk_command = command.into_chunk(chunk_size, chunk_index, false);
			self._send_single_command(chunk_command, response_length_encoding, send_buffer, receive_buffers, |response_data, response_code|
			{
				let data_length = response_data.len();
				if unlikely!(data_length != 0)
				{
					return Err(CardError::TransmitChunkOtherThanFinalHadResponseData { data_length })
				}
				
				match response_code
				{
					ResponseCode::Ok => Ok(()),
					
					ResponseCode::ClassFunctionError(ClassFunctionError::LastCommandOfTheChainExpected) => Ok(()),
					
					ResponseCode::ClassFunctionError(ClassFunctionError::CommandChainingNotSupported) => Err(CardError::TransmitCardLiedAboutSupportingChainedCommands),
					
					// too much data sent.
					ResponseCode::StateOfNonVolatileMemoryUnchangedWarning(StateOfNonVolatileMemoryUnchangedWarning::EndOfFileOrRecordReachedBeforeReadingLeBytes) => Err(CardError::TransmitCardOutOfMemory),
					
					_ => Err(CardError::TransmitChunkOtherThanFinalHadUnexpectedError(response_code))
				}
			})??;
		}
		
		let chunk_command = command.into_chunk(chunk_size, final_chunk_index, true);
		self._send_single_command(chunk_command, response_length_encoding, send_buffer, receive_buffers, |response_data, response_code| response.process_response(response_data, response_code))?
	}
	
	/// To use a `response_length_encoding` of `Long`, the card needs to support extended length for Lc and Le.
	fn _send_single_command<'buffers, Callback: FnOnce(&'buffers [u8], ResponseCode) -> R, R>(&self, command: ApplicationProtocolDataUnitCommand, response_length_encoding: ResponseLengthEncoding, send_buffer: &'buffers mut SendBuffer, receive_buffers: &'buffers mut ReceiveBuffers, response: Callback) -> Result<R, CardError>
	{
		let send_buffer = command.serialize(response_length_encoding, send_buffer);
		let receive_buffer = receive_buffers.reserve_receive(response_length_encoding);
		let received_buffer = self._transmit_wrapper(send_buffer, receive_buffer).map_err(CardError::Transmit)?;
		
		let (response_data, response_code) = ResponseCode::extract_response_data_and_response_code(received_buffer)?;
		
		Ok(response(response_data, response_code))
	}
	
	#[doc(hidden)]
	fn _transmit_wrapper<'receive_buffer>(&self, send_buffer: &[u8], receive_buffer: &'receive_buffer mut [u8]) -> Result<&'receive_buffer [u8], pcsc::Error>;
	
	fn send_control<Callback: FnOnce(&[u8]) -> R, R>(&self, control_code: u32, send_buffer: &[u8], callback: Callback) -> Result<R, CardError>;
	
	fn finish(self, disposition: Disposition) -> Result<(), CardError>;
}

macro_rules! _status2_len_wrapper
{
	() =>
	{
		#[inline(always)]
		fn _status2_len_wrapper(&self) -> Result<(usize, usize), pcsc::Error>
		{
			self.status2_len()
		}
	}
}

macro_rules! _status2_wrapper
{
	() =>
	{
		#[inline(always)]
		fn _status2_wrapper<'names_buf, 'atr_buf>(&self, reader_names_buffer: &'names_buf mut [u8], answer_to_reset_buffer: &'atr_buf mut [u8]) -> Result<CardStatus<'names_buf, 'atr_buf>, pcsc::Error>
		{
			self.status2(reader_names_buffer, answer_to_reset_buffer)
		}
	}
}

macro_rules! get_attribute_value
{
	() =>
	{
		#[inline(always)]
		fn get_attribute_value<Callback: FnOnce(&[u8]) -> R, R>(&self, attribute: Attribute, callback: Callback) -> Result<R, CardError>
		{
			use self::CardError::*;
			
			let attribute_length = self.get_attribute_len(attribute).map_err(GetAttributeLength)?;
			let mut attribute_buffer = Vec::new_buffer(attribute_length)?;
			let attribute = self.get_attribute(attribute, &mut attribute_buffer).map_err(GetAttribute)?;
			
			Ok(callback(attribute))
		}
	}
}

macro_rules! set_attribute_value
{
	() =>
	{
		#[inline(always)]
		fn set_attribute_value(&self, attribute: Attribute, attribute_data: &[u8]) -> Result<(), CardError>
		{
			self.set_attribute(attribute, attribute_data).map_err(CardError::SetAttribute)
		}
	}
}

macro_rules! _transmit_wrapper
{
	() =>
	{
		#[inline(always)]
		fn _transmit_wrapper<'receive_buffer>(&self, send_buffer: &[u8], receive_buffer: &'receive_buffer mut [u8]) -> Result<&'receive_buffer [u8], pcsc::Error>
		{
			self.transmit(send_buffer, receive_buffer)
		}
	}
}
macro_rules! send_control
{
	() =>
	{
		#[inline(always)]
		fn send_control<Callback: FnOnce(&[u8]) -> R, R>(&self, control_code: u32, send_buffer: &[u8], callback: Callback) -> Result<R, CardError>
		{
			let mut receive_buffer = Vec::new_buffer(MAX_BUFFER_SIZE_EXTENDED)?;
			let receive_buffer = self.control(control_code, send_buffer, &mut receive_buffer).map_err(CardError::Control)?;
			Ok(callback(receive_buffer))
		}
	}
}

impl CardOrTransactionExt for Card
{
	_status2_len_wrapper!();
	
	_status2_wrapper!();
	
	get_attribute_value!();
	
	set_attribute_value!();
	
	_transmit_wrapper!();
	
	send_control!();
	
	#[inline(always)]
	fn finish(self, disposition: Disposition) -> Result<(), CardError>
	{
		// self.en()
		match self.disconnect(disposition)
		{
			Ok(()) => Ok(()),
			
			Err((_card, error)) => Err(CardError::Finish(error))
		}
	}
}

impl<'tx> CardOrTransactionExt for Transaction<'tx>
{
	_status2_len_wrapper!();
	
	_status2_wrapper!();
	
	get_attribute_value!();
	
	set_attribute_value!();
	
	_transmit_wrapper!();
	
	send_control!();
	
	#[inline(always)]
	fn finish(self, disposition: Disposition) -> Result<(), CardError>
	{
		match self.end(disposition)
		{
			Ok(()) => Ok(()),
			
			Err((_transaction, error)) => Err(CardError::Finish(error))
		}
	}
}
