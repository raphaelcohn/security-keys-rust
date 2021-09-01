// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version2AudioStreamingInterfaceExtraDescriptorParseError
{
	#[allow(missing_docs)]
	GeneralParse(GeneralParseError),
	
	#[allow(missing_docs)]
	EncoderParse(EncoderParseError),
	
	#[allow(missing_docs)]
	FormatTypeIsUnexpected,
	
	#[allow(missing_docs)]
	DecoderParse(DecoderParseError),
}

impl Display for Version2AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version2AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		match self
		{
			GeneralParse(cause) => Some(cause),
			
			EncoderParse(cause) => Some(cause),
			
			DecoderParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}
