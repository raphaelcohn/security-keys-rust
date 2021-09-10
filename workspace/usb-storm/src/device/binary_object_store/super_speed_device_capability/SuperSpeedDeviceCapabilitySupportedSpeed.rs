// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Supported super speed.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u16)]
pub enum SuperSpeedDeviceCapabilitySupportedSpeed
{
	/// The device is operating at low speed (1.5 Mbps).
	Low = 0b0001,
	
	/// The device is operating at full speed (12 Mbps).
	Full = 0b0010,
	
	/// The device is operating at high speed (480 Mbps).
	High = 0b0100,
	
	/// The device is operating at super speed (5 Gbps).
	Super = 0b1000,
}
