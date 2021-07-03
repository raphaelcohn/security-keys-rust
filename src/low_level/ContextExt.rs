// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(super) trait ContextExt: Sized
{
	fn new_user_scope() -> Result<Self, ContextError>;
	
	fn use_reader_names<Callback: FnOnce(&mut ReaderNames) -> R, R>(&self, callback: Callback) -> Result<R, ContextError>;
	
	fn connect_to_card_reader_shared(&self, reader_name: &CStr) -> Result<Option<Card>, ContextError>;
}

impl ContextExt for Context
{
	#[inline(always)]
	fn new_user_scope() -> Result<Self, ContextError>
	{
		Context::establish(Scope::User).map_err(ContextError::EstablishAContextWithUserScope)
	}
	
	#[inline(always)]
	fn use_reader_names<Callback: FnOnce(&mut ReaderNames) -> R, R>(&self, callback: Callback) -> Result<R, ContextError>
	{
		use self::ContextError::*;
		
		let reader_names_length = self.list_readers_len().map_err(ListReadersLength)?;
		let mut reader_names_buffer = Vec::new_buffer(reader_names_length)?;
		let mut reader_names = self.list_readers(&mut reader_names_buffer).map_err(ListReaders)?;
		Ok(callback(&mut reader_names))
	}
	
	#[inline(always)]
	fn connect_to_card_reader_shared(&self, reader_name: &CStr) -> Result<Option<Card>, ContextError>
	{
		match self.connect(&reader_name, ShareMode::Shared, Protocols::ANY)
		{
			Ok(card) => Ok(Some(card)),
			
			Err(pcsc::Error::NoSmartcard) => Ok(None),
			
			Err(error) => Err(ContextError::ConnectShared(error))
		}
	}
}
