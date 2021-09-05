// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version2ProcessTypeParseError
{
	#[allow(missing_docs)]
	Undefined(Version2UndefinedProcessTypeParseError),
	
	#[allow(missing_docs)]
	UpDownMixParse(Version2UpDownMixProcessTypeParseError),
	
	#[allow(missing_docs)]
	DolbyProLogicParse(Version2DolbyProLogicProcessTypeParseError),
	
	#[allow(missing_docs)]
	StereoExtenderParse(Version2StereoExtenderProcessTypeParseError),
	
	#[allow(missing_docs)]
	Unrecognized(Version2UnrecognizedProcessTypeParseError),
}

impl Display for Version2ProcessTypeParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2ProcessTypeParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version2ProcessTypeParseError::*;
		
		match self
		{
			UpDownMixParse(cause) => Some(cause),
			
			DolbyProLogicParse(cause) => Some(cause),
			
			StereoExtenderParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<Version2UndefinedProcessTypeParseError> for Version2ProcessTypeParseError
{
	#[inline(always)]
	fn from(cause: Version2UndefinedProcessTypeParseError) -> Self
	{
		Version2ProcessTypeParseError::Undefined(cause)
	}
}

impl From<Version2UpDownMixProcessTypeParseError> for Version2ProcessTypeParseError
{
	#[inline(always)]
	fn from(cause: Version2UpDownMixProcessTypeParseError) -> Self
	{
		Version2ProcessTypeParseError::UpDownMixParse(cause)
	}
}

impl From<Version2DolbyProLogicProcessTypeParseError> for Version2ProcessTypeParseError
{
	#[inline(always)]
	fn from(cause: Version2DolbyProLogicProcessTypeParseError) -> Self
	{
		Version2ProcessTypeParseError::DolbyProLogicParse(cause)
	}
}

impl From<Version2StereoExtenderProcessTypeParseError> for Version2ProcessTypeParseError
{
	#[inline(always)]
	fn from(cause: Version2StereoExtenderProcessTypeParseError) -> Self
	{
		Version2ProcessTypeParseError::StereoExtenderParse(cause)
	}
}

impl From<Version2UnrecognizedProcessTypeParseError> for Version2ProcessTypeParseError
{
	#[inline(always)]
	fn from(cause: Version2UnrecognizedProcessTypeParseError) -> Self
	{
		Version2ProcessTypeParseError::Unrecognized(cause)
	}
}
