// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum FormatTypeIIIParseError
{
	#[allow(missing_docs)]
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	SamplingFrequencyParse(SamplingFrequencyParseError),
	
	#[allow(missing_docs)]
	InvalidSubframeSize
	{
		bSubframeSize: u8,
	},
	
	#[allow(missing_docs)]
	InvalidBitResolution
	{
		bBitResolution: u8,
	},
}

impl Display for FormatTypeIIIParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for FormatTypeIIIParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use FormatTypeIIIParseError::*;
		
		match self
		{
			SamplingFrequencyParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}
