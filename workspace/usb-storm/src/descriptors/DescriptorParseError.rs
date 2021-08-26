// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Descriptor parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorParseError<E: error::Error>
{
	/// libusb returned null for extra; should not be possible, but trusting third party C libraries is the way to madness.
	ExtraIsNullButLengthIsNonZero,
	
	/// libusb returned a negative length for extra; should not be possible, but trusting third party C libraries is the way to madness.
	ExtraLengthIsNegative,
	
	/// At a minimum, a descriptor must consist of a length byte (`bLength`) and a type byte (`bDescriptorType`).
	NotEnoughDescriptorBytes,

	/// The length byte `bLength` of a descriptor is longer than the number of bytes remaining to parse.
	DescriptorLengthExceedsRemainingBytes,

	/// An error specific to to the specific (sic) extra descriptor being parsed.
	Specific(E),

	#[allow(missing_docs)]
	CanNotAllocateUnknownDescriptorBuffer(TryReserveError),
	
	#[allow(missing_docs)]
	CanNotAllocateExtraDescriptor(TryReserveError),
}

impl<E: error::Error> Display for DescriptorParseError<E>
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl<E: 'static + error::Error> error::Error for DescriptorParseError<E>
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use DescriptorParseError::*;
		
		match self
		{
			Specific(cause) => Some(cause),
			
			CanNotAllocateUnknownDescriptorBuffer(cause) => Some(cause),
			
			CanNotAllocateExtraDescriptor(cause) => Some(cause),
			
			_ => None,
		}
	}
}
