// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A serious error when getting a string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum GetWebUrlError
{
	TooShort
	{
		vendor_code: u8,
		
		url_descriptor_index: NonZeroU8,
	},
	
	GetStandardUsbDescriptor
	{
		cause: GetStandardUsbDescriptorError,
		
		vendor_code: u8,
		
		url_descriptor_index: NonZeroU8,
	},
	
	CouldNotAllocateMemory
	{
		cause: TryReserveError,
		
		vendor_code: u8,
		
		url_descriptor_index: NonZeroU8,
	},
	
	NotValidUtf8
	{
		cause: FromUtf8Error,
		
		vendor_code: u8,
		
		url_descriptor_index: NonZeroU8,
	},
}

impl Display for GetWebUrlError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for GetWebUrlError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use GetWebUrlError::*;
		
		match self
		{
			GetStandardUsbDescriptor { cause, .. } => Some(cause),
			
			CouldNotAllocateMemory { cause, .. } => Some(cause),
			
			NotValidUtf8 { cause, .. } => Some(cause),
			
			_ => None,
		}
	}
}
