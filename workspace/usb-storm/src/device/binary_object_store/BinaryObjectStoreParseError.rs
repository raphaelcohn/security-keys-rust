// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A parse error.
#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum BinaryObjectStoreParseError
{
	CouldNotGet(GetStandardUsbDescriptorError),
	
	TooShort
	{
		/// Less than 3 bytes.
		remaining_length: usize,
	},
	
	CouldNotAllocateMemoryForDeviceCapabilities(TryReserveError),
	
	CouldNotParseDeviceCapability
	{
		cause: DeviceCapabilityParseError,
		
		index: u8,
	}
}

impl Display for BinaryObjectStoreParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for BinaryObjectStoreParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use BinaryObjectStoreParseError::*;
		
		match self
		{
			CouldNotGet(cause) => Some(cause),
			
			CouldNotAllocateMemoryForDeviceCapabilities(cause) => Some(cause),
			
			CouldNotParseDeviceCapability { cause, .. } => Some(cause),
			
			_ => None,
		}
	}
}

impl From<GetStandardUsbDescriptorError> for BinaryObjectStoreParseError
{
	#[inline(always)]
	fn from(cause: GetStandardUsbDescriptorError) -> Self
	{
		BinaryObjectStoreParseError::CouldNotGet(cause)
	}
}

impl From<TryReserveError> for BinaryObjectStoreParseError
{
	#[inline(always)]
	fn from(cause: TryReserveError) -> Self
	{
		BinaryObjectStoreParseError::CouldNotAllocateMemoryForDeviceCapabilities(cause)
	}
}
