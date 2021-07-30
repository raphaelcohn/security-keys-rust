// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum CommandNotAllowedError
{
	/// The command is not allowed.
	NoInformationGiven,
	
	/// Inactive state.
	CommandNotAccepted,
	
	CommandIncompatibleWithFileStructure,
	
	SecurityConditionNotSatisified,
	
	AuthenticationMethodBlocked,
	
	/// Invalidated.
	ReferenceDataReversiblyBlocked,
	
	ConditionsOfUseNotSatisified,
	
	/// Not current EF.
	CommandNotAllowed,
	
	/// `SM`: Secure Messaging.
	ExpectedSecureMessagingObjectMissing,
	
	IncorrectSecureMessagingDataObject,
	
	Reserved,
	
	DataMustBeUpdatedAgain,
	
	/// `POL1`: Policy 1.
	POL1_OfTheCurrentlyEnabledProfilePreventsThisAction,
	
	PermissionDenied,
	
	PermissionDeniedMissingPrivilege,
	
	/// No description.
	NoDocumentationOfMeaning
	{
		/// Values are in the range `2 ..= 15`.
		value: u4,
	},

	ReservedForFutureUse
	{
		sw2: u8,
	},
}

impl CommandNotAllowedError
{
	#[inline(always)]
	fn categorize_response_code(sw2: u8) -> Self
	{
		use CommandNotAllowedError::*;
		
		match sw2
		{
			0x00 => NoInformationGiven,
			
			0x01 => CommandNotAccepted,
			
			0x81 => CommandIncompatibleWithFileStructure,
			
			0x82 => SecurityConditionNotSatisified,
			
			0x83 => AuthenticationMethodBlocked,
			
			0x84 => ReferenceDataReversiblyBlocked,
			
			0x85 => ConditionsOfUseNotSatisified,
			
			0x86 => CommandNotAllowed,
			
			0x87 => ExpectedSecureMessagingObjectMissing,
			
			0x88 => IncorrectSecureMessagingDataObject,
			
			0x8D => Reserved,
			
			0x96 => DataMustBeUpdatedAgain,
			
			0xE1 => POL1_OfTheCurrentlyEnabledProfilePreventsThisAction,
			
			0xF0 => PermissionDenied,
			
			0xF1 => PermissionDeniedMissingPrivilege,
			
			0xF2 ..= 0xFF => NoDocumentationOfMeaning
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
