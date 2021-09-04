// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Logical power switching mode.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u8)]
pub enum LogicalPowerSwitchingMode
{
	/// All ports' power switches at once.
	Ganged = 0b00,

	#[allow(missing_docs)]
	IndividualPort = 0b01,
	
	#[allow(missing_docs)]
	Usb_1_0_Reserved0 = 0b10,
	
	#[allow(missing_docs)]
	Usb_1_0_Reserved1 = 0b11,
}
