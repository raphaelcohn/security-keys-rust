// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A serious error when getting a string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum GetLocalizedStringError
{
	StringIndexNonZeroButDeviceDoesNotSupportLanguages
	{
		string_descriptor_index: NonZeroU8,
	},
	
	/// Either the string descriptor is not internally valid in the device, or the device has decided to not support this language for this string descriptor index.
	///
	/// Either way, it's a broken device.
	StringIndexNonZeroButDeviceDoesNotSupportGettingString
	{
		string_descriptor_index: NonZeroU8,
		
		language: Language,
	},
	
	GetStandardUsbDescriptor
	{
		cause: GetStandardUsbDescriptorError,
		
		string_descriptor_index: NonZeroU8,
	
		language: Language,
	},
	
	NotACorrectUtf16LittleEndianSize
	{
		string_descriptor_index: NonZeroU8,
		
		language: Language,
	},
	
	CouldNotAllocateString
	{
		cause: TryReserveError,
		
		string_descriptor_index: NonZeroU8,
		
		language: Language,
	},

	InvalidUtf16LittleEndianSequence
	{
		cause: DecodeUtf16Error,
		
		string_descriptor_index: NonZeroU8,
		
		language: Language,
	},
}

impl Display for GetLocalizedStringError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for GetLocalizedStringError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use GetLocalizedStringError::*;
		
		match self
		{
			GetStandardUsbDescriptor { cause, .. } => Some(cause),
			
			CouldNotAllocateString { cause, .. } => Some(cause),
			
			InvalidUtf16LittleEndianSequence { cause, .. } => Some(cause),
			
			_ => None,
		}
	}
}
