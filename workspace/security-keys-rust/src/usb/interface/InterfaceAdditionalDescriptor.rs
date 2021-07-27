// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum InterfaceAdditionalDescriptor
{
	SmartCard(SmartCardInterfaceAdditionalDescriptor),
	
	HumanInterfaceDevice(HumanInterfaceDeviceInterfaceAdditionalDescriptor),
}

impl From<SmartCardInterfaceAdditionalDescriptor> for InterfaceAdditionalDescriptor
{
	#[inline(always)]
	fn from(value: SmartCardInterfaceAdditionalDescriptor) -> Self
	{
		InterfaceAdditionalDescriptor::SmartCard(value)
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

impl From<UnsupportedInterfaceAdditionalDescriptor> for InterfaceAdditionalDescriptor
{
	#[inline(always)]
	fn from(value: UnsupportedInterfaceAdditionalDescriptor) -> Self
	{
		unreachable!("Should never be possible as it is impossible to construct an instance of UnsupportedInterfaceAdditionalDescriptor")
	}
}
