// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum StringParseError
{
	#[allow(missing_docs)]
	StringMinimumCanNotBeFollowedByStringMinimum,
	
	#[allow(missing_docs)]
	StringMaximumMustBePreceededByStringMinimum,
	
	#[allow(missing_docs)]
	StringMinimumMustBeLessThanMaximum,
	
	#[allow(missing_docs)]
	StringMinimumNotFollowedByStringMaximum,
	
	#[allow(missing_docs)]
	StringDescriptorIndexOutOfRange
	{
		data: u32,
	},
	
	#[allow(missing_docs)]
	CouldNotFindString(GetLocalizedStringError),
	
	#[allow(missing_docs)]
	CouldNotPushStringItem(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
}

impl Display for StringParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for StringParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use StringParseError::*;
		
		match self
		{
			CouldNotFindString(cause) => Some(cause),
			
			CouldNotPushStringItem(cause) => Some(cause),
			
			_ => None,
		}
	}
}
