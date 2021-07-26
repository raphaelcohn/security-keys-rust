// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum StateOfNonVolatileMemoryChangedError
{
	NoInformationGiven,
	
	/// There have been problems in writing or reading the EEPROM.
	/// Other hardware problems may also bring this error.
	WriteErrorOrMemoryFailue,
	
	MemoryFailure,
	
	/// No description.
	NoDocumentationOfMeaning
	{
		/// Values are in the range `0 ..= 15`.
		value: u4,
	},
	
	ReservedForFutureUse
	{
		sw2: u8,
	}
}

impl StateOfNonVolatileMemoryChangedError
{
	#[inline(always)]
	fn categorize_response_code(sw2: u8) -> Self
	{
		use self::StateOfNonVolatileMemoryChangedError::*;
		
		match sw2
		{
			0x00 => NoInformationGiven,
			
			0x01 => WriteErrorOrMemoryFailue,
			
			0x81 => MemoryFailure,
			
			0xF0 ..= 0xFF => NoDocumentationOfMeaning
			{
				value: sw2 - 0xF0,
			},
			
			_ => ReservedForFutureUse
			{
				sw2
			}
		}
	}
}
