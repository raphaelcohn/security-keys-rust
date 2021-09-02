// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatTypeParseError
{
	#[allow(missing_docs)]
	NoFormatTypeDescriptorBytes,
	
	#[allow(missing_docs)]
	BLengthIsLessThanDescriptorHeaderLength,
	
	#[allow(missing_docs)]
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	BLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	DescriptorTypeIsNotInterface
	{
		bDescriptorType: DescriptorType,
	},
	
	#[allow(missing_docs)]
	DescriptorSubTypeIsNotFormatType
	{
		bDescriptorSubType: DescriptorSubType,
	},
	
	#[allow(missing_docs)]
	UndefinedFormatTypeCode
	{
		audio_format: Version1AudioFormat,
	},
	
	#[allow(missing_docs)]
	UnrecognizedFormatTypeCode
	{
		audio_format: Version1AudioFormat,
		
		bFormatType: u8,
	},
	
	#[allow(missing_docs)]
	FormatTypeIParse(FormatTypeIParseError),
	
	#[allow(missing_docs)]
	FormatTypeIIParse(FormatTypeIIParseError),
	
	#[allow(missing_docs)]
	FormatTypeIIIParse(FormatTypeIIIParseError),
}

impl Display for FormatTypeParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for FormatTypeParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use FormatTypeParseError::*;
		
		match self
		{
			FormatTypeIParse(cause) => Some(cause),
			
			FormatTypeIIParse(cause) => Some(cause),
			
			FormatTypeIIIParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<FormatTypeIParseError> for FormatTypeParseError
{
	#[inline(always)]
	fn from(cause: FormatTypeIParseError) -> Self
	{
		FormatTypeParseError::FormatTypeIParse(cause)
	}
}

impl From<FormatTypeIIParseError> for FormatTypeParseError
{
	#[inline(always)]
	fn from(cause: FormatTypeIIParseError) -> Self
	{
		FormatTypeParseError::FormatTypeIIParse(cause)
	}
}

impl From<FormatTypeIIIParseError> for FormatTypeParseError
{
	#[inline(always)]
	fn from(cause: FormatTypeIIIParseError) -> Self
	{
		FormatTypeParseError::FormatTypeIIIParse(cause)
	}
}
