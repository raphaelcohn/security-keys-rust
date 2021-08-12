// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Interface additional descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum InterfaceAdditionalDescriptor
{
	#[allow(missing_docs)]
	DeviceFirmwareUpgrade(DeviceFirmwareUpgradeInterfaceAdditionalDescriptor),
	
	#[allow(missing_docs)]
	HumanInterfaceDevice(HumanInterfaceDeviceInterfaceAdditionalDescriptor),
	
	#[allow(missing_docs)]
	SmartCard(SmartCardInterfaceAdditionalDescriptor),
}

impl From<DeviceFirmwareUpgradeInterfaceAdditionalDescriptor> for InterfaceAdditionalDescriptor
{
	#[inline(always)]
	fn from(value: DeviceFirmwareUpgradeInterfaceAdditionalDescriptor) -> Self
	{
		InterfaceAdditionalDescriptor::DeviceFirmwareUpgrade(value)
	}
}

impl From<HumanInterfaceDeviceInterfaceAdditionalDescriptor> for InterfaceAdditionalDescriptor
{
	#[inline(always)]
	fn from(value: HumanInterfaceDeviceInterfaceAdditionalDescriptor) -> Self
	{
		InterfaceAdditionalDescriptor::HumanInterfaceDevice(value)
	}
}

impl From<SmartCardInterfaceAdditionalDescriptor> for InterfaceAdditionalDescriptor
{
	#[inline(always)]
	fn from(value: SmartCardInterfaceAdditionalDescriptor) -> Self
	{
		InterfaceAdditionalDescriptor::SmartCard(value)
	}
}

impl From<UnsupportedInterfaceAdditionalDescriptor> for InterfaceAdditionalDescriptor
{
	#[inline(always)]
	fn from(_value: UnsupportedInterfaceAdditionalDescriptor) -> Self
	{
		unreachable!("Should never be possible as it is impossible to construct an instance of UnsupportedInterfaceAdditionalDescriptor")
	}
}
