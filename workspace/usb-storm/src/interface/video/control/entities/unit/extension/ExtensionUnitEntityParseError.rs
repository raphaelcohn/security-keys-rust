// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ExtensionUnitEntityParseError
{
	#[allow(missing_docs)]
	BLengthTooShort
	{
		bLength: u8,
	},
	
	#[allow(missing_docs)]
	SourcesParse(SourcesParseError),
	
	#[allow(missing_docs)]
	BLengthTooShortForControlSize
	{
		bLength: u8,
		
		bControlSize: u8,
	},
	
	/// Whilst in theory it is possible to have 255 controls, this is incredibly unlikely.
	///
	/// Restricting to 64 controls allows the use of a fixed-size bit map.
	MoreThan64ExtensionControlsAreNotSupported
	{
		#[allow(missing_docs)]
		bNumControls: u8,
	},
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
}

impl Display for ExtensionUnitEntityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for ExtensionUnitEntityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use ExtensionUnitEntityParseError::*;
		
		match self
		{
			SourcesParse(cause) => Some(cause),
			
			InvalidDescriptionString(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<SourcesParseError> for ExtensionUnitEntityParseError
{
	#[inline(always)]
	fn from(cause: SourcesParseError) -> Self
	{
		ExtensionUnitEntityParseError::SourcesParse(cause)
	}
}
