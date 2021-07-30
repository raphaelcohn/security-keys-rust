// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum StateOfNonVolatileMemoryUnchangedWarning
{
	NoInformationGiven,
	
	NonVolatileRamNotChanged,

	PartOfReturnedDataMayBeCorrupted,
	
	EndOfFileOrRecordReachedBeforeReadingLeBytes,

	SelectedFileInvalidated,

	/// 'FCI not formated according to ISO'.
	SelectedFileIsNotValid,
	
	// 'No Purse Engine enslaved for R3bc'.
	NoInputDataAvailableFromASensorOnTheCard,
	
	/// 'R-MAC'.
	WrongRMac,
	
	CardLockedDuringReset,

	Counter
	{
		value: u4,
	},
	
	/// 'C-MAC'.
	WrongCMac,
	
	InternalReset,
	
	DefaultAgentLocked,
	
	CardholderLocked,
	
	BasementIsCurrentAgent,

	CALCKeySetNotUnblocked,

	/// No description.
	NoDocumentationOfMeaning
	{
		/// Values are in the range `10 ..= 15`.
		value: u4,
	},

	ReservedForFutureUse
	{
		sw2: u8,
	}
}

impl StateOfNonVolatileMemoryUnchangedWarning
{
	#[inline(always)]
	fn categorize_response_code(sw2: u8) -> Self
	{
		use StateOfNonVolatileMemoryUnchangedWarning::*;
		
		match sw2
		{
			0x00 => NoInformationGiven,
			
			0x01 => NonVolatileRamNotChanged,
			
			0x81 => PartOfReturnedDataMayBeCorrupted,
			
			0x82 => EndOfFileOrRecordReachedBeforeReadingLeBytes,
			
			0x83 => SelectedFileInvalidated,
			
			0x84 => SelectedFileIsNotValid,
			
			0x85 => NoInputDataAvailableFromASensorOnTheCard,
			
			0xA2 => WrongRMac,
			
			0xA4 => CardLockedDuringReset,
			
			0xC0 ..= 0xCF => Counter { value: sw2 - 0xC0 },
			
			0xF1 => WrongCMac,
			
			0xF3 => InternalReset,
			
			0xF5 => DefaultAgentLocked,
			
			0xF7 => CardholderLocked,
			
			0xF8 => BasementIsCurrentAgent,
			
			0xF9 => CALCKeySetNotUnblocked,
			
			0xFA ..= 0xFF => NoDocumentationOfMeaning
			{
				value: sw2 - 0xF0
			},
			
			_ => ReservedForFutureUse
			{
				sw2
			}
		}
	}
}
