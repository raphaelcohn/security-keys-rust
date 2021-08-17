// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A program error.
#[derive(Debug)]
pub(super) enum ProgramError
{
	#[allow(missing_docs)]
	CouldNotCreateOutputFile(io::Error),
	
	#[allow(missing_docs)]
	ContextInitialization(ContextInitializationError),
	
	#[allow(missing_docs)]
	ListDevices(ListDevicesError),
	
	#[allow(missing_docs)]
	CouldNotCreateBinaryObjectStoreBuffer(TryReserveError),
	
	#[allow(missing_docs)]
	DevicesParse(DevicesParseError),
	
	#[allow(missing_docs)]
	Serializing(SerializingError),
}

impl Display for ProgramError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for ProgramError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use ProgramError::*;
		
		match self
		{
			CouldNotCreateOutputFile(cause) => Some(cause),
			
			ContextInitialization(cause) => Some(cause),
			
			ListDevices(cause) => Some(cause),
			
			CouldNotCreateBinaryObjectStoreBuffer(cause) => Some(cause),
			
			DevicesParse(cause) => Some(cause),
			
			Serializing(cause) => Some(cause),
		}
	}
}

impl From<ContextInitializationError> for ProgramError
{
	#[inline(always)]
	fn from(cause: ContextInitializationError) -> Self
	{
		ProgramError::ContextInitialization(cause)
	}
}

impl From<ListDevicesError> for ProgramError
{
	#[inline(always)]
	fn from(cause: ListDevicesError) -> Self
	{
		ProgramError::ListDevices(cause)
	}
}

impl From<DevicesParseError> for ProgramError
{
	#[inline(always)]
	fn from(cause: DevicesParseError) -> Self
	{
		ProgramError::DevicesParse(cause)
	}
}

impl From<SerializingError> for ProgramError
{
	#[inline(always)]
	fn from(cause: SerializingError) -> Self
	{
		ProgramError::Serializing(cause)
	}
}
