// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum UsbSpeed
{
	/// The operating system doesn't know the device speed.
	Unknown,
	
	/// The device is operating at low speed (1.5 Mbps).
	Low,
	
	/// The device is operating at full speed (12 Mbps).
	Full,
	
	/// The device is operating at high speed (480 Mbps).
	High,
	
	/// The device is operating at super speed (5 Gbps).
	Super,
}

impl From<Speed> for UsbSpeed
{
	#[inline(always)]
	fn from(speed: Speed) -> Self
	{
		match speed
		{
			Speed::Unknown => UsbSpeed::Unknown,
			
			Speed::Low => UsbSpeed::Low,
			
			Speed::Full => UsbSpeed::Full,
			
			Speed::High => UsbSpeed::High,
			
			Speed::Super => UsbSpeed::Super,
		}
	}
}
