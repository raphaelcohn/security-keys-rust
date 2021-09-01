// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ac3EncoderParseError
{
	#[allow(missing_docs)]
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	BLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	ControlParse(DecoderControlParseError),
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
	
	#[allow(missing_docs)]
	Ac3MustSupportBitStreamIdModes0To9Inclusive,
}

impl Display for Ac3EncoderParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Ac3EncoderParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Ac3EncoderParseError::*;
		
		match self
		{
			ControlParse(cause) => Some(cause),
			
			InvalidDescriptionString(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<DecoderControlParseError> for Ac3EncoderParseError
{
	#[inline(always)]
	fn from(cause: DecoderControlParseError) -> Self
	{
		Ac3EncoderParseError::ControlParse(cause)
	}
}

impl From<GetLocalizedStringError> for Ac3EncoderParseError
{
	#[inline(always)]
	fn from(cause: GetLocalizedStringError) -> Self
	{
		Ac3EncoderParseError::InvalidDescriptionString(cause)
	}
}
