// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Version2HubDescriptorParseError
{
	#[allow(missing_docs)]
	GetDescriptor(GetStandardUsbDescriptorError),
	
	#[allow(missing_docs)]
	HubDescriptorTooShort,
	
	#[allow(missing_docs)]
	TooFewVariableBytes,
	
	#[allow(missing_docs)]
	WhilstUsb2PermitsAValueOf255HereWeUseANonZeroU8ForPortNumber,
	
	#[allow(missing_docs)]
	CouldNotAllocatePortsSettings(TryReserveError),
}

impl Display for Version2HubDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2HubDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version2HubDescriptorParseError::*;
		
		match self
		{
			GetDescriptor(cause) => Some(cause),
			
			CouldNotAllocatePortsSettings(cause) => Some(cause),
			
			_ => None,
		}
	}
}
