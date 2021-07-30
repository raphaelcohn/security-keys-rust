// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Configuration descriptor parse error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum ConfigurationParseError
{
	#[allow(missing_docs)]
	WrongLength
	{
		bLength: u8,
	},
	
	#[allow(missing_docs)]
	WrongDescriptorType
	{
		bDescriptorType: u8,
	},
	
	#[allow(missing_docs)]
	WrongTotalLength
	{
		wTotalLength: u16
	},
	
	/// Apparently, there are some buggy devices that report an `bConfigurationValue` of 0!
	ConfigurationValueWasZero,
	
	#[allow(missing_docs)]
	AttributesBitSevenIsNotOne,
	
	#[allow(missing_docs)]
	AttributesBitsZeroToFourAreNotZero,
	
	#[allow(missing_docs)]
	DeviceIsOnlyBusPoweredAndHasZeroMaximumPowerConsumption,
	
	#[allow(missing_docs)]
	NoInterfaces,
	
	#[allow(missing_docs)]
	TooManyInterfaces
	{
		bNumInterfaces: u8
	},
	
	/// Bug in libusb.
	NullInterfacePointer,
	
	// #[allow(missing_docs)]
	// CouldNotAllocateInterfaces(TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotParseInterface
	{
		cause: InterfaceParseError,
		
		interface_index: u5,
	},
	
	#[allow(missing_docs)]
	DuplicateInterface
	{
		interface_index: u5,
		
		interface_number: InterfaceNumber,
	},
}

impl Display for ConfigurationParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for ConfigurationParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use self::ConfigurationParseError::*;
		
		match self
		{
			CouldNotParseInterface { cause, .. } => Some(cause),
			
			_ => None,
		}
	}
}
