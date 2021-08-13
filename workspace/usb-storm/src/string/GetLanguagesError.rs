// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A serious error when getting languages.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum GetLanguagesError
{
	GetStandardUsbDescriptor(GetStandardUsbDescriptorError),
	
	NotACorrectArraySize,
	
	CouldNotAllocateDuplicateLanguages(TryReserveError),
	
	CouldNotAllocateLanguages(TryReserveError),
	
	DuplicateLanguage
	{
		language: Language,
	},
}

impl Display for GetLanguagesError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for GetLanguagesError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use GetLanguagesError::*;
		
		match self
		{
			GetStandardUsbDescriptor(cause) => Some(cause),
			
			CouldNotAllocateDuplicateLanguages(cause) => Some(cause),
			
			CouldNotAllocateLanguages(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<GetStandardUsbDescriptorError> for GetLanguagesError
{
	#[inline(always)]
	fn from(cause: GetStandardUsbDescriptorError) -> Self
	{
		GetLanguagesError::GetStandardUsbDescriptor(cause)
	}
}
