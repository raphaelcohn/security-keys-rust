// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Human Interface Device (HID) descriptor parse error.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EndPointParseError
{
	/// Reserved bits are set in `bEndpointAddress`.
	EndpointAddressHasReservedBits,
	
	/// This can happen if the end point is repeated with two different directions.
	DuplicateEndPointNumber(EndPointNumber),
	
	/// Transfer type.
	TransferType(TransferTypeParseError),
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
		use self::EndPointParseError::*;
		
		match self
		{
			TransferType(cause) => Some(cause),
			
			_ => None,
		}
	}
}
