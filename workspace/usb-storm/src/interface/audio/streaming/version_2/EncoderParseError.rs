// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum EncoderParseError
{
	#[allow(missing_docs)]
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	BLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	BitRateControlInvalid,
	
	#[allow(missing_docs)]
	QualityControlInvalid,
	
	#[allow(missing_docs)]
	VbrControlInvalid,
	
	#[allow(missing_docs)]
	TypeControlInvalid,
	
	#[allow(missing_docs)]
	UnderflowControlInvalid,
	
	#[allow(missing_docs)]
	OverflowControlInvalid,
	
	#[allow(missing_docs)]
	EncoderErrorControlInvalid,
	
	#[allow(missing_docs)]
	ParameterControlInvalid
	{
		/// Add one to this to get the control number.
		///
		/// Does not exceed 7.
		index: u3,
	},
	
	#[allow(missing_docs)]
	InvalidParameterControlDescriptionString
	{
		cause: GetLocalizedStringError,
		
		/// Add one to this to get the control number.
		///
		/// Does not exceed 7.
		index: u3,
	},
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
}

impl Display for EncoderParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for EncoderParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use EncoderParseError::*;
		
		match self
		{
			InvalidParameterControlDescriptionString { cause, .. } => Some(cause),
			
			InvalidDescriptionString(cause) => Some(cause),
			
			_ => None,
		}
	}
}
