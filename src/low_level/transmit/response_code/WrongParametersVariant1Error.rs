// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// Covers Parameters P1 and P2.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum WrongParametersVariant1Error
{
	NoInformationGiven,

	TheParametersInTheDataFieldAreIncorrect,

	FunctionNotSupported,

	FileNotFound,

	RecordNotFound,

	ThereIsInsufficientMemorySpaceInTheRecordOrFile,
	
	LengthLcInconsistentWithTagLengthValueStructure,

	IncorrectP1OrP2Parameter,

	LengthLcInconsistentWithP1OrP2,

	ReferencedDataNotFound,

	FileAlreadyExists,

	DFNameAlreadyExists,

	WrongParameterValue,
	
	/// No description.
	NoDocumentationOfMeaning
	{
		/// Values are in the range `1 ..= 15`.
		value: u4,
	},

	ReservedForFutureUse
	{
		sw2: u8,
	}
}

impl WrongParametersVariant1Error
{
	#[inline(always)]
	fn categorize_response_code(sw2: u8) -> Self
	{
		use self::WrongParametersVariant1Error::*;
		
		match sw2
		{
			0x00 => NoInformationGiven,
			
			0x80 => TheParametersInTheDataFieldAreIncorrect,
			
			0x81 => FunctionNotSupported,
			
			0x82 => FileNotFound,
			
			0x83 => RecordNotFound,
			
			0x84 => ThereIsInsufficientMemorySpaceInTheRecordOrFile,
			
			0x85 => LengthLcInconsistentWithTagLengthValueStructure,
			
			0x86 => IncorrectP1OrP2Parameter,
			
			0x87 => LengthLcInconsistentWithP1OrP2,
			
			0x88 => ReferencedDataNotFound,
			
			0x89 => FileAlreadyExists,
			
			0x8A => DFNameAlreadyExists,
			
			0xF0 => WrongParameterValue,
			
			0xF1 ..= 0xFF => NoDocumentationOfMeaning
			{
				value: sw2 - 0xF0,
			},
			
			_ => ReservedForFutureUse
			{
				sw2
			},
/*
0xFX => –
0xXX => ReservedForFutureUse
 */
		}
	}
}
