// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Human Interface Device (HID) descriptor parse error.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum InterfaceAdditionalDescriptorParseError
{
	HumanInterfaceDevice(HumanInterfaceDeviceInterfaceAdditionalDescriptorParseError),
	
	SmartCard(SmartCardInterfaceAdditionalDescriptorParseError),
}

impl Display for InterfaceAdditionalDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for InterfaceAdditionalDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use self::InterfaceAdditionalDescriptorParseError::*;
		
		match self
		{
			HumanInterfaceDevice(cause) => Some(cause),
			
			SmartCard(cause) => Some(cause),
		}
	}
}

impl From<HumanInterfaceDeviceInterfaceAdditionalDescriptorParseError> for InterfaceAdditionalDescriptorParseError
{
	#[inline(always)]
	fn from(cause: HumanInterfaceDeviceInterfaceAdditionalDescriptorParseError) -> Self
	{
		InterfaceAdditionalDescriptorParseError::HumanInterfaceDevice(cause)
	}
}

impl From<SmartCardInterfaceAdditionalDescriptorParseError> for InterfaceAdditionalDescriptorParseError
{
	#[inline(always)]
	fn from(cause: SmartCardInterfaceAdditionalDescriptorParseError) -> Self
	{
		InterfaceAdditionalDescriptorParseError::SmartCard(cause)
	}
}

impl From<Infallible> for InterfaceAdditionalDescriptorParseError
{
	#[inline(always)]
	fn from(_cause: Infallible) -> Self
	{
		unreachable!("UnsupportedInterfaceAdditionalDescriptorParser can not construct Infallible")
	}
}
