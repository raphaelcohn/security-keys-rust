// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpegEncoderParseError
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
	ReservedMpeg2MultilingualSupport,
}

impl Display for MpegEncoderParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for MpegEncoderParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use MpegEncoderParseError::*;
		
		match self
		{
			ControlParse(cause) => Some(cause),
			
			InvalidDescriptionString(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<DecoderControlParseError> for MpegEncoderParseError
{
	#[inline(always)]
	fn from(cause: DecoderControlParseError) -> Self
	{
		MpegEncoderParseError::ControlParse(cause)
	}
}

impl From<GetLocalizedStringError> for MpegEncoderParseError
{
	#[inline(always)]
	fn from(cause: GetLocalizedStringError) -> Self
	{
		MpegEncoderParseError::InvalidDescriptionString(cause)
	}
}
