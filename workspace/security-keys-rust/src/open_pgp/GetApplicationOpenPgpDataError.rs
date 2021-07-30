// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum GetApplicationOpenPgpDataError
{
	Card(CardError),
	
	TagLengthValueParse(TagLengthValueParseError),
	
	MissingApplicationIdentifier,

	ApplicationIdentifierParse(ApplicationIdentifierParseError),
}

impl Display for GetApplicationOpenPgpDataError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for GetApplicationOpenPgpDataError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use GetApplicationOpenPgpDataError::*;
		
		match self
		{
			Card(cause) => Some(cause),
			
			TagLengthValueParse(cause) => Some(cause),
			
			MissingApplicationIdentifier => None,
			
			ApplicationIdentifierParse(cause) => Some(cause),
		}
	}
}

impl From<CardError> for GetApplicationOpenPgpDataError
{
	#[inline(always)]
	fn from(cause: CardError) -> Self
	{
		GetApplicationOpenPgpDataError::Card(cause)
	}
}

impl From<TagLengthValueParseError> for GetApplicationOpenPgpDataError
{
	#[inline(always)]
	fn from(cause: TagLengthValueParseError) -> Self
	{
		GetApplicationOpenPgpDataError::TagLengthValueParse(cause)
	}
}

impl From<ApplicationIdentifierParseError> for GetApplicationOpenPgpDataError
{
	#[inline(always)]
	fn from(cause: ApplicationIdentifierParseError) -> Self
	{
		GetApplicationOpenPgpDataError::ApplicationIdentifierParse(cause)
	}
}
