// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Port setting.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Version2DownstreamPortSetting
{
	device_is_removable: bool,
	
	usb_1_0_power_control: bool,
}

impl DownstreamPortSetting for Version2DownstreamPortSetting
{
	#[inline(always)]
	fn device_is_removable(&self) -> bool
	{
		self.device_is_removable
	}
}

impl Version2DownstreamPortSetting
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn usb_1_0_power_control(&self) -> bool
	{
		self.usb_1_0_power_control
	}
}
