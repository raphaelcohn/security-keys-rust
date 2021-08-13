// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Interface additional descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum InterfaceExtraDescriptor
{
	#[allow(missing_docs)]
	DeviceFirmwareUpgrade(DeviceFirmwareUpgradeInterfaceExtraDescriptor),
	
	#[allow(missing_docs)]
	HumanInterfaceDevice(HumanInterfaceDeviceInterfaceExtraDescriptor),
	
	#[allow(missing_docs)]
	SmartCard(SmartCardInterfaceExtraDescriptor),
}

impl From<DeviceFirmwareUpgradeInterfaceExtraDescriptor> for InterfaceExtraDescriptor
{
	#[inline(always)]
	fn from(value: DeviceFirmwareUpgradeInterfaceExtraDescriptor) -> Self
	{
		InterfaceExtraDescriptor::DeviceFirmwareUpgrade(value)
	}
}

impl From<HumanInterfaceDeviceInterfaceExtraDescriptor> for InterfaceExtraDescriptor
{
	#[inline(always)]
	fn from(value: HumanInterfaceDeviceInterfaceExtraDescriptor) -> Self
	{
		InterfaceExtraDescriptor::HumanInterfaceDevice(value)
	}
}

impl From<SmartCardInterfaceExtraDescriptor> for InterfaceExtraDescriptor
{
	#[inline(always)]
	fn from(value: SmartCardInterfaceExtraDescriptor) -> Self
	{
		InterfaceExtraDescriptor::SmartCard(value)
	}
}

impl From<UnsupportedInterfaceExtraDescriptor> for InterfaceExtraDescriptor
{
	#[inline(always)]
	fn from(_value: UnsupportedInterfaceExtraDescriptor) -> Self
	{
		unreachable!("Should never be possible as it is impossible to construct an instance of UnsupportedInterfaceAdditionalDescriptor")
	}
}
