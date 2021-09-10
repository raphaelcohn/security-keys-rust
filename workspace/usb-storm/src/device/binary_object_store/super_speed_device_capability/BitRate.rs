// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Bit rate as powers of ten.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
// `#[repr(u2)]`
#[repr(u8)]
enum BitRate
{
	/// This is 1 bit / second (bps).
	BitsPerSecond = 0,

	/// Kb/s (Kbit).
	///
	/// This is a 1,000 bit / second (bps).
	KilobitsPerSecond = 1,
	
	/// Mb/s (Mbit).
	///
	/// This is a 1,000,000 bit / second (bps).
	MegabitsPerSecond = 2,
	
	/// Gb/s (Gbit).
	///
	/// This is a 1,000,000,000 bit / second (bps).
	GigabitsPerSecond = 3,
}
