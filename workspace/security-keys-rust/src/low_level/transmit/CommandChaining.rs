// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


pub(crate) enum CommandChaining
{
	Unsupported,

	Supported
	{
		chunk_size: NonZeroU16,
	}
}

impl CommandChaining
{
	#[inline(always)]
	pub(super) fn send_command(self, card_or_transaction: &impl CardOrTransactionExt, command: ApplicationProtocolDataUnitCommand, response_length_encoding: ResponseLengthEncoding, send_buffer: &mut SendBuffer, receive_buffers: &mut ReceiveBuffers, response: &mut Response) -> Result<bool, CardError>
	{
		use self::CommandChaining::*;
		
		response.clear();
		
		match self
		{
			Unsupported => card_or_transaction._send_single_command(command, response_length_encoding, send_buffer, receive_buffers, |response_data, response_code| response.process_response(response_data, response_code))?,
			
			Supported { chunk_size } => card_or_transaction._send_chained_command(command, response_length_encoding, send_buffer, receive_buffers, response, chunk_size)
		}
	}
}
