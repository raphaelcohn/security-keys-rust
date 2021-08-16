// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version2FeatureUnitEntityParseError
{
	#[allow(missing_docs)]
	ControlsLengthNotAMultipleOfFour,
	
	ChannelControlInvalid
	{
		cause: Version2FeatureUnitEntityChannelControlParseError,
		
		channel_index: u8,
	},
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
}

impl Display for Version2FeatureUnitEntityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2FeatureUnitEntityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version2FeatureUnitEntityParseError::*;
		
		match self
		{
			InvalidDescriptionString(cause) => Some(cause),
			
			ChannelControlInvalid { cause, .. } => Some(cause),
			
			_ => None,
		}
	}
}

impl From<Version2FeatureTypeParseError> for Version2FeatureUnitEntityParseError
{
	#[inline(always)]
	fn from(cause: Version2FeatureTypeParseError) -> Self
	{
		Version2FeatureUnitEntityParseError::FeatureTypeParse(cause)
	}
}
