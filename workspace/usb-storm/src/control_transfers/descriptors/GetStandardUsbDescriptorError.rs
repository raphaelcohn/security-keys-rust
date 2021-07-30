// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An error when getting a descriptor.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum GetStandardUsbDescriptorError
{
	#[allow(missing_docs)]
	ControlTransfer(ControlTransferError),
	
	#[allow(missing_docs)]
	StandardUsbDescriptor(StandardUsbDescriptorError),
}

impl Display for GetStandardUsbDescriptorError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for GetStandardUsbDescriptorError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use self::GetStandardUsbDescriptorError::*;
		
		match self
		{
			ControlTransfer(cause) => Some(cause),
		}
	}
}

impl From<ControlTransferError> for GetStandardUsbDescriptorError
{
	#[inline(always)]
	fn from(cause: ControlTransferError) -> Self
	{
		GetStandardUsbDescriptorError::ControlTransfer(cause)
	}
}

impl From<StandardUsbDescriptorError> for GetStandardUsbDescriptorError
{
	#[inline(always)]
	fn from(cause: StandardUsbDescriptorError) -> Self
	{
		GetStandardUsbDescriptorError::StandardUsbDescriptor(cause)
	}
}
