// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
enum ApplicationIdentifierParseError
{
	ShouldBePrimitive,
	
	WrongLength
	{
		length: usize,
	},

	WrongApplicationSelected
	{
		registed_application_provider_identifier: RegisteredApplicationProviderIdentifier,
	},
	
	SmartChessProprietaryApplicationUnsupported,
	
	ReservedProprietaryApplicationUnsupported,
	
	UnknownProprietaryApplication
	{
		proprietary_application_identifier_extension: ProprietaryApplicationIdentifierExtension,
	},
	
	UnknownReservedValue
	{
		reserved: u16,
	}
}

impl Display for ApplicationIdentifierParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for ApplicationIdentifierParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use ApplicationIdentifierParseError::*;
		
		match self
		{
			ShouldBePrimitive => None,
			
			WrongLength { .. } => None,
			
			WrongApplicationSelected { .. } => None,
			
			SmartChessProprietaryApplicationUnsupported => None,
			
			ReservedProprietaryApplicationUnsupported => None,
			
			UnknownProprietaryApplication { .. } => None,
			
			UnknownReservedValue { .. } => None,
		}
	}
}
