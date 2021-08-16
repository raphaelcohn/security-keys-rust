// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version2InputTerminalEntityParseError
{
	#[allow(missing_docs)]
	TerminalTypeIsOutputOnly,
	
	#[allow(missing_docs)]
	LogicalAudioChannelClusterParse(LogicalAudioChannelClusterParseError<Version2LogicalAudioChannelClusterParseError>),
	
	#[allow(missing_docs)]
	CopyProtectControlInvalid,
	
	#[allow(missing_docs)]
	ConnectorControlInvalid,
	
	#[allow(missing_docs)]
	OverloadControlInvalid,
	
	#[allow(missing_docs)]
	ClusterControlInvalid,
	
	#[allow(missing_docs)]
	UnderflowControlInvalid,
	
	#[allow(missing_docs)]
	OverflowControlInvalid,
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
}

impl Display for Version2InputTerminalEntityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2InputTerminalEntityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version2InputTerminalEntityParseError::*;
		
		match self
		{
			InvalidDescriptionString(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<LogicalAudioChannelClusterParseError<Version2LogicalAudioChannelClusterParseError>> for Version2InputTerminalEntityParseError
{
	#[inline(always)]
	fn from(cause: LogicalAudioChannelClusterParseError<Version2LogicalAudioChannelClusterParseError>) -> Self
	{
		Version2InputTerminalEntityParseError::LogicalAudioChannelClusterParse(cause)
	}
}
