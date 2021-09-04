// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An error when getting a descriptor.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum GetDescriptorError
{
	/// `LIBUSB_ERROR_OVERFLOW`.
	ControlRequestBufferOverflow,
	
	/// Failed to allocate heap memory.
	///
	/// `LIBUSB_ERROR_NO_MEM`.
	ControlRequestOutOfMemory,
	
	/// `LIBUSB_ERROR_OTHER`.
	ControlRequestOther,
}

impl Display for GetDescriptorError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for GetDescriptorError
{
}

impl GetDescriptorError
{
	#[inline(always)]
	pub(crate) fn parse_result(result: Result<&[u8], ControlTransferError>) -> Result<DeadOrAlive<Option<&[u8]>>, Self>
	{
		use ControlTransferError::*;
		use GetDescriptorError::*;
		
		match result
		{
			Ok(bytes) => Ok(Alive(Some(bytes))),
			
			Err(TransferInputOutputErrorOrTransferCancelled) => Ok(Dead),
			
			Err(DeviceDisconnected) => Ok(Dead),
			
			Err(RequestedResourceNotFound) => unreachable!("RequestedResourceNotFound should not occur for GET_DESCRIPTOR or similar"),
			
			Err(TimedOut) => Ok(Dead),
			
			Err(BufferOverflow) => Err(ControlRequestBufferOverflow),
			
			Err(NotSupported { .. }) => Ok(Alive(None)),
			
			Err(OutOfMemory) => Err(ControlRequestOutOfMemory),
			
			Err(Other) => Err(ControlRequestOther),
		}
	}
}
