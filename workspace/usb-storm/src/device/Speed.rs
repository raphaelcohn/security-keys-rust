// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Speed.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
// `#[repr(NonZeroU8)]`
#[repr(u8)]
pub enum Speed
{
	/// The device is operating at low speed (1.5 Mbps).
	Low = 1,
	
	/// The device is operating at full speed (12 Mbps).
	Full = 2,
	
	/// The device is operating at high speed (480 Mbps).
	High = 3,
	
	/// The device is operating at super speed (5 Gbps).
	///
	/// Only possible for USB 3.0+.
	Super = 4,
	
	/// The device is operating at super speed plus (10 Gbps).
	///
	/// Only possible for USB 3.0+.
	SuperPlus = 5,
}

impl Speed
{
	/// Is this a Gen X speed?
	#[inline(always)]
	pub fn is_gen_x_speed(self) -> bool
	{
		use Speed::*;
		
		self == Super || self == SuperPlus
	}
}
