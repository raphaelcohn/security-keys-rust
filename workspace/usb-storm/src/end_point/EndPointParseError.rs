// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// End Point descriptor parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndPointParseError
{
	/// ?Bug in libusb.
	WrongLength
	{
		#[allow(missing_docs)]
		bLength: u8
	},
	
	/// ?Bug in libusb.
	WrongDescriptorType
	{
		#[allow(missing_docs)]
		bDescriptorType: DescriptorType
	},
	
	/// Reserved bits are set in `bEndpointAddress`.
	EndpointAddressHasReservedBits,
	
	/// Transfer type.
	TransferType(TransferTypeParseError),
	
	#[allow(missing_docs)]
	CouldNotParseEndPointAdditionalDescriptor(DescriptorParseError<EndPointExtraDescriptorParseError>),
}

impl Display for EndPointParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for EndPointParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use EndPointParseError::*;
		
		match self
		{
			TransferType(cause) => Some(cause),
			
			CouldNotParseEndPointAdditionalDescriptor(cause) => Some(cause),
			
			_ => None,
		}
	}
}
