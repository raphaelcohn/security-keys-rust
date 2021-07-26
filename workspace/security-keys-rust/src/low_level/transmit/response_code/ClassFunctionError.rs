// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum ClassFunctionError
{
	/// The requested function is not supported by the card.
	NoInformationGiven,

	LogicalChannelNotSupported,

	SecureMessagingNotSupported,

	LastCommandOfTheChainExpected,

	CommandChainingNotSupported,
	
	/// No description.
	NoDocumentationOfMeaning
	{
		/// Values are in the range `2 ..= 15`.
		value: u4,
	},

	ReservedForFutureUse
	{
		sw2: u8,
	}
}

impl ClassFunctionError
{
	#[inline(always)]
	fn categorize_response_code(sw2: u8) -> Self
	{
		use self::ClassFunctionError::*;
		
		match sw2
		{
			0x00 => NoInformationGiven,
			
			0x81 => LogicalChannelNotSupported,
			
			0x82 => SecureMessagingNotSupported,
			
			0x83 => LastCommandOfTheChainExpected,
			
			0x84 => CommandChainingNotSupported,
			
			0xF0 ..= 0xFF => NoDocumentationOfMeaning
			{
				value: sw2 - 0xF0,
			},
			
			_ => ReservedForFutureUse
			{
				sw2
			},
		}
	}
}
