// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Human Interface Device (HID) descriptor parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceExtraDescriptorParseError
{
	/// Device Firmware Upgrade (DFU).
	DeviceFirmwareUpgrade(DeviceFirmwareUpgradeInterfaceExtraDescriptorParseError),
	
	/// Human Interface Device (HID).
	HumanInterfaceDevice(HumanInterfaceDeviceInterfaceExtraDescriptorParseError),
	
	/// Smart Card (CCID).
	SmartCard(SmartCardInterfaceExtraDescriptorParseError),
}

impl Display for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use InterfaceExtraDescriptorParseError::*;
		
		match self
		{
			DeviceFirmwareUpgrade(cause) => Some(cause),
			
			HumanInterfaceDevice(cause) => Some(cause),
			
			SmartCard(cause) => Some(cause),
		}
	}
}

impl From<DeviceFirmwareUpgradeInterfaceExtraDescriptorParseError> for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: DeviceFirmwareUpgradeInterfaceExtraDescriptorParseError) -> Self
	{
		InterfaceExtraDescriptorParseError::DeviceFirmwareUpgrade(cause)
	}
}

impl From<HumanInterfaceDeviceInterfaceExtraDescriptorParseError> for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: HumanInterfaceDeviceInterfaceExtraDescriptorParseError) -> Self
	{
		InterfaceExtraDescriptorParseError::HumanInterfaceDevice(cause)
	}
}

impl From<SmartCardInterfaceExtraDescriptorParseError> for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: SmartCardInterfaceExtraDescriptorParseError) -> Self
	{
		InterfaceExtraDescriptorParseError::SmartCard(cause)
	}
}

impl From<Infallible> for InterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(_cause: Infallible) -> Self
	{
		unreachable!("UnsupportedInterfaceAdditionalDescriptorParser can not construct Infallible")
	}
}
