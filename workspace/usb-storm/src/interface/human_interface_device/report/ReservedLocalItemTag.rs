// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A reserved local item tag.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u8)]
pub enum ReservedLocalItemTag
{
	/// 0.
	#[serde(rename = "0")] _0 = 0b0110,
	
	/// 1.
	#[serde(rename = "1")] _1 = 0b1011,
	
	/// 2.
	#[serde(rename = "2")] _2 = 0b1100,
	
	/// 3.
	#[serde(rename = "3")] _3 = 0b1101,
	
	/// 4.
	#[serde(rename = "4")] _4 = 0b1110,
}
