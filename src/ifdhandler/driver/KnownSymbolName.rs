// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum KnownSymbolName
{
	IFDHCloseChannel,
	
	IFDHControl,
	
	IFDHCreateChannel,
	
	IFDHCreateChannelByName,
	
	IFDHGetCapabilities,
	
	IFDHICCPresence,
	
	IFDHPowerICC,
	
	IFDHSetCapabilities,
	
	IFDHSetProtocolParameters,
	
	IFDHTransmitToICC,
}

impl KnownSymbolName
{
	#[inline(always)]
	fn c_string_bytes(self) -> &'static [u8]
	{
		use self::KnownSymbolName::*;
		
		match self
		{
			IFDHCloseChannel => b"IFDHCloseChannel\0" as &[u8],
			
			IFDHControl => b"IFDHControl\0" as &[u8],
			
			IFDHCreateChannel => b"IFDHCreateChannel\0" as &[u8],
			
			IFDHCreateChannelByName => b"IFDHCreateChannelByName\0" as &[u8],
			
			IFDHGetCapabilities => b"IFDHGetCapabilities\0" as &[u8],
			
			IFDHICCPresence => b"IFDHICCPresence\0" as &[u8],
			
			IFDHPowerICC => b"IFDHPowerICC\0" as &[u8],
			
			IFDHSetCapabilities => b"IFDHSetCapabilities\0" as &[u8],
			
			IFDHSetProtocolParameters => b"IFDHSetProtocolParameters\0" as &[u8],
			
			IFDHTransmitToICC => b"IFDHTransmitToICC\0" as &[u8],
		}
	}
	
	#[inline(always)]
	fn get_symbol<'lib, T: 'lib>(self, library: &'lib Library) -> Result<RawSymbol<T>, LoadDriverError>
	{
		let symbol_name = self.c_string_bytes();
		let symbol: Result<libloading::Symbol<'lib, T>, libloading::Error> = unsafe { library.get(symbol_name) };
		match symbol
		{
			Ok(symbol) => Ok(unsafe { symbol.into_raw() }),
			
			Err(cause) => Err(LoadDriverError::GetSymbol { cause, known_symbol_name: self })
		}
	}
}
