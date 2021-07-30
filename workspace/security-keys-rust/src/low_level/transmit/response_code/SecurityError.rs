// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum SecurityError
{
	TimeoutWhileWhileReceiving,

	CharacterParityErrorWhileReceiving,
	
	WrongChecksum,
	
	TheCurrentDFFileIsWithoutFCI,
	
	NoSFOrKFUnderTheCurrentDF,
	
	IncorrectEncryptionOrDecryptionPadding,
	
	/// No description.
	NoDocumentationOfMeaning
	{
		/// Values are in the range `0 ..= 15`.
		value: u4,
	},
	
	ReservedForFutureUse
	{
		sw2: u8,
	},
}

impl SecurityError
{
	#[inline(always)]
	fn categorize_response_code(sw2: u8) -> Self
	{
		use SecurityError::*;
		
		match sw2
		{
			0x00 => TimeoutWhileWhileReceiving,
			
			0x01 => CharacterParityErrorWhileReceiving,
			
			0x02 => WrongChecksum,
			
			0x03 => TheCurrentDFFileIsWithoutFCI,
			
			0x04 => NoSFOrKFUnderTheCurrentDF,
			
			0x69 => IncorrectEncryptionOrDecryptionPadding,
			
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
