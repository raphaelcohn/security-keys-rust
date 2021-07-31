// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug)]
pub(super) enum SerializingError
{
	#[allow(missing_docs)]
	Simple(SimpleSerializerError),
	
	#[allow(missing_docs)]
	YetAnotherMarkupLanguage(serde_yaml::Error),
	
	#[allow(missing_docs)]
	RustyObjectNotation(ron::Error),
	
	#[allow(missing_docs)]
	LispSExpression(serde_lexpr::Error),
}

impl Display for SerializingError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for SerializingError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use SerializingError::*;
		
		match self
		{
			Simple(cause) => Some(cause),
			
			YetAnotherMarkupLanguage(cause) => Some(cause),
			
			RustyObjectNotation(cause) => Some(cause),
			
			LispSExpression(cause) => Some(cause),
		}
	}
}

impl From<SimpleSerializerError> for SerializingError
{
	#[inline(always)]
	fn from(cause: SimpleSerializerError) -> Self
	{
		SerializingError::Simple(cause)
	}
}

impl From<serde_yaml::Error> for SerializingError
{
	#[inline(always)]
	fn from(cause: serde_yaml::Error) -> Self
	{
		SerializingError::YetAnotherMarkupLanguage(cause)
	}
}

impl From<ron::Error> for SerializingError
{
	#[inline(always)]
	fn from(cause: ron::Error) -> Self
	{
		SerializingError::RustyObjectNotation(cause)
	}
}

impl From<serde_lexpr::Error> for SerializingError
{
	#[inline(always)]
	fn from(cause: serde_lexpr::Error) -> Self
	{
		SerializingError::LispSExpression(cause)
	}
}
