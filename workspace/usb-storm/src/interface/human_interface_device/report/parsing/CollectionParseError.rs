// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum CollectionParseError
{
	#[allow(missing_docs)]
	Stack(StackError),
	
	#[allow(missing_docs)]
	UnclosedCollection,
	
	#[allow(missing_docs)]
	TooManyCollectionPops,
	
	#[allow(missing_docs)]
	EndCollectionCanNotHaveData
	{
		data: NonZeroU32,
	},
	
	#[allow(missing_docs)]
	NoUsagePage,
}

impl Display for CollectionParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for CollectionParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use CollectionParseError::*;
		
		match self
		{
			Stack(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<StackError> for CollectionParseError
{
	#[inline(always)]
	fn from(cause: StackError) -> Self
	{
		CollectionParseError::Stack(cause)
	}
}
