// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


pub(crate) struct ReceiveBuffers
{
	receive_none: [u8; ReceiveBuffers::SWLength],
	
	receive_short: [u8; 256 + ReceiveBuffers::SWLength],
	
	receive_long: Vec<u8>,
}

impl ReceiveBuffers
{
	const SWLength: usize = 2;
	
	#[allow(deprecated)]
	#[inline(always)]
	pub(super) fn allocate() -> Result<Self, TryReserveError>
	{
		Ok
		(
			Self
			{
				receive_none: unsafe { uninitialized() },
				
				receive_short: unsafe { uninitialized() },
				
				receive_long: Vec::new_buffer(MAX_BUFFER_SIZE_EXTENDED + Self::SWLength)?,
			}
		)
	}
	
	#[inline(always)]
	pub(super) fn reserve_receive(&mut self, response_length_encoding: ResponseLengthEncoding) -> &mut [u8]
	{
		use ResponseLengthEncoding::*;
		
		match response_length_encoding
		{
			None => &mut self.receive_none,
			
			Short => &mut self.receive_short,
			
			Long =>
			{
				self.receive_long.clear();
				&mut self.receive_long
			},
		}
	}
}
