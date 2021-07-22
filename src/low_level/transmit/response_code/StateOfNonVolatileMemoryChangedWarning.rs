// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum StateOfNonVolatileMemoryChangedWarning
{
	NoInformationGiven,

	/// Loading or updating is not allowed.
	FileFilledUpByTheLastWrite,

	CardKeyNotSupported,

	ReaderKeyNotSupported,

	PlaintextTransmissionNotSupported,

	SecuredTransmissionNotSupported,

	VolatileMemoryIsNotAvailable,

	NonVolatileMemoryIsNotAvailable,

	KeyNumberNotValid,

	KeyLengthIsNotCorrect,

	/// If this is a pin verify command, the value will be the number of tries left in the range `0..=3`.
	Counter
	{
		value: u4,
	},
	
	MoreDataExpected,
	
	MoreDataExpectedAndProActiveCommandPending,
	
	/// No description.
	NoDocumentationOfMeaning
	{
		/// Values are in the range `3 ..= 15`.
		value: u4,
	},
	
	ReservedForFutureUse
	{
		sw2: u8,
	}
}

impl StateOfNonVolatileMemoryChangedWarning
{
	#[inline(always)]
	fn categorize_response_code(sw2: u8) -> Self
	{
		use self::StateOfNonVolatileMemoryChangedWarning::*;
		
		match sw2
		{
			0x00 => NoInformationGiven,
			
			0x81 => FileFilledUpByTheLastWrite,
			
			0x82 => CardKeyNotSupported,
			
			0x83 => ReaderKeyNotSupported,
			
			0x84 => PlaintextTransmissionNotSupported,
			
			0x85 => SecuredTransmissionNotSupported,
			
			0x86 => VolatileMemoryIsNotAvailable,
			
			0x87 => NonVolatileMemoryIsNotAvailable,
			
			0x88 => KeyNumberNotValid,
			
			0x89 => KeyLengthIsNotCorrect,
			
			0xC0 ..= 0xCF => Counter
			{
				value: sw2 - 0xC0,
			},
			
			0xF1 => MoreDataExpected,
			
			0xF2 => MoreDataExpectedAndProActiveCommandPending,
			
			0xF3 ..= 0xFF => NoDocumentationOfMeaning
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
