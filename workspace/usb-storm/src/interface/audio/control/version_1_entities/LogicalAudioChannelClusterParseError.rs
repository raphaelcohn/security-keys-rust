// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogicalAudioChannelClusterParseError
{
	#[allow(missing_docs)]
	NumberOfLogicalAudioChannelsIsLessThanNumberOfSpatialLogicalAudioChannels,
	
	#[allow(missing_docs)]
	NamedLogicalAudioChannelStringIdentifierGreaterThan255,
	
	#[allow(missing_docs)]
	ChannelNameString
	{
		cause: GetLocalizedStringError,
	
		channel_index: u8,
	},
}

impl Display for LogicalAudioChannelClusterParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for LogicalAudioChannelClusterParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use LogicalAudioChannelClusterParseError::*;
		
		match self
		{
			ChannelNameString { cause, .. } => Some(cause),
			
			_ => None,
		}
	}
}
