// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version2ProcessingUnitEntityParseError
{
	#[allow(missing_docs)]
	ProcessTypeParse(Version2ProcessTypeParseError),
	
	#[allow(missing_docs)]
	PIsTooLarge,
	
	#[allow(missing_docs)]
	EnableControlInvalid,
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
}

impl Display for Version2ProcessingUnitEntityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2ProcessingUnitEntityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version2ProcessingUnitEntityParseError::*;
		
		match self
		{
			ProcessTypeParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<Version2ProcessTypeParseError> for Version2ProcessingUnitEntityParseError
{
	#[inline(always)]
	fn from(cause: Version2ProcessTypeParseError) -> Self
	{
		Version2ProcessingUnitEntityParseError::ProcessTypeParse(cause)
	}
}
