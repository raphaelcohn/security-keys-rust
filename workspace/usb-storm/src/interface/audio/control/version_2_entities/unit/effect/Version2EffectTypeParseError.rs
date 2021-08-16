// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version2EffectTypeParseError<ControlsError: error::Error>
{
	#[allow(missing_docs)]
	ControlsLengthNotAMultipleOfFour,
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForControls(TryReserveError),
	
	ChannelControlInvalid
	{
		cause: ControlsError,
		
		channel_index: u8,
	},
}

impl<ControlsError: error::Error> Display for Version2EffectTypeParseError<ControlsError>
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl<ControlsError: 'static + error::Error> error::Error for Version2EffectTypeParseError<ControlsError>
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version2EffectTypeParseError::*;
		
		match self
		{
			CouldNotAllocateMemoryForControls(cause) => Some(cause),
			
			ChannelControlInvalid { cause, .. } => Some(cause),
			
			_ => None,
		}
	}
}
