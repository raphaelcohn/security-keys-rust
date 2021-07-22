// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


pub(crate) struct Response(Vec<u8>);

impl Deref for Response
{
	type Target = Vec<u8>;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

impl DerefMut for Response
{
	#[inline(always)]
	fn deref_mut(&mut self) -> &mut Self::Target
	{
		&mut self.0
	}
}

impl Response
{
	#[inline(always)]
	pub(super) fn new() -> Result<Self, TryReserveError>
	{
		Ok(Self(Vec::new_with_capacity(MAX_BUFFER_SIZE_EXTENDED)?))
	}
	
	#[inline(always)]
	pub(super) fn process_response(&mut self, response_data: &[u8], response_code: ResponseCode) -> Result<bool, CardError>
	{
		let more_response_data_to_receive = match response_code
		{
			ResponseCode::Ok => false,
			
			ResponseCode::ResponseBytesStillAvailable { .. } => true,
			
			_ => false,
		};
		
		self.0.try_reserve_exact(response_data.len()).map_err(CardError::OutOfMemoryAllocatingBuffer)?;
		self.0.extend_from_slice(response_data);
		Ok(more_response_data_to_receive)
	}
}
