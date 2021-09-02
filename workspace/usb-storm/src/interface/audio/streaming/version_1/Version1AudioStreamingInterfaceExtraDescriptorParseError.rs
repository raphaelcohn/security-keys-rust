// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version1AudioStreamingInterfaceExtraDescriptorParseError
{
	#[allow(missing_docs)]
	GenericParse(GenericAudioStreamingInterfaceExtraDescriptorParseError),
	
	#[allow(missing_docs)]
	FormatTypeIsUnexpected,
	
	#[allow(missing_docs)]
	FormatSpecificIsUnexpected,
	
	#[allow(missing_docs)]
	GeneralBLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	GeneralBLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	FormatTypeParse(FormatTypeParseError),
}

impl Display for Version1AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version1AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version1AudioStreamingInterfaceExtraDescriptorParseError::*;
		
		match self
		{
			GenericParse(cause) => Some(cause),
			
			FormatTypeParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<GenericAudioStreamingInterfaceExtraDescriptorParseError> for Version1AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: GenericAudioStreamingInterfaceExtraDescriptorParseError) -> Self
	{
		Version1AudioStreamingInterfaceExtraDescriptorParseError::GenericParse(cause)
	}
}

impl From<FormatTypeParseError> for Version1AudioStreamingInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: FormatTypeParseError) -> Self
	{
		Version1AudioStreamingInterfaceExtraDescriptorParseError::FormatTypeParse(cause)
	}
}
