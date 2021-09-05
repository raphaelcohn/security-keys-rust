// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum DecoderParseError
{
	#[allow(missing_docs)]
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	BLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	MpegParse(MpegEncoderParseError),
	
	#[allow(missing_docs)]
	Ac3Parse(Ac3EncoderParseError),
	
	#[allow(missing_docs)]
	WmaParse(WmaEncoderParseError),
	
	#[allow(missing_docs)]
	DtsParse(DtsEncoderParseError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForUndefinedOrOtherOrUnrecognizedData(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
}

impl Display for DecoderParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for DecoderParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use DecoderParseError::*;
		
		match self
		{
			MpegParse(cause) => Some(cause),
			
			Ac3Parse(cause) => Some(cause),
			
			WmaParse(cause) => Some(cause),
			
			DtsParse(cause) => Some(cause),
			
			CouldNotAllocateMemoryForUndefinedOrOtherOrUnrecognizedData(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<MpegEncoderParseError> for DecoderParseError
{
	#[inline(always)]
	fn from(cause: MpegEncoderParseError) -> Self
	{
		DecoderParseError::MpegParse(cause)
	}
}

impl From<Ac3EncoderParseError> for DecoderParseError
{
	#[inline(always)]
	fn from(cause: Ac3EncoderParseError) -> Self
	{
		DecoderParseError::Ac3Parse(cause)
	}
}

impl From<WmaEncoderParseError> for DecoderParseError
{
	#[inline(always)]
	fn from(cause: WmaEncoderParseError) -> Self
	{
		DecoderParseError::WmaParse(cause)
	}
}

impl From<DtsEncoderParseError> for DecoderParseError
{
	#[inline(always)]
	fn from(cause: DtsEncoderParseError) -> Self
	{
		DecoderParseError::DtsParse(cause)
	}
}
