// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version3EntityDescriptorParseError
{
	#[allow(missing_docs)]
	LatencyControlInvalid,
	
	#[allow(missing_docs)]
	ExtendedTerminalIsAHighCapacityDescriptor,
	
	#[allow(missing_docs)]
	ConnectorsIsAHighCapacityDescriptor,
	
	#[allow(missing_docs)]
	AudioDynamicStringDescriptorIdentifierIsOutOfRange,
	
	#[allow(missing_docs)]
	TerminalTypeIsOutputOnly,
	
	#[allow(missing_docs)]
	TerminalTypeIsInputOnly,
	
	#[allow(missing_docs)]
	TerminalControlsParse(TerminalControlsParseError),
}

impl Display for Version3EntityDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version3EntityDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version3EntityDescriptorParseError::*;
		
		match self
		{
			TerminalControlsParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<TerminalControlsParseError> for Version3EntityDescriptorParseError
{
	#[inline(always)]
	fn from(cause: TerminalControlsParseError) -> Self
	{
		Version3EntityDescriptorParseError::TerminalControlsParse(cause)
	}
}
