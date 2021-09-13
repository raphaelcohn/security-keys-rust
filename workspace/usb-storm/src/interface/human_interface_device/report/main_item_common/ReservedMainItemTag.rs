// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A reserved main item tag.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u8)]
pub enum ReservedMainItemTag
{
	/// 0.
	#[serde(rename = "0")] _0 = 0b0000,
	
	/// 1.
	#[serde(rename = "1")] _1 = 0b0001,
	
	/// 2.
	#[serde(rename = "2")] _2 = 0b0010,
	
	/// 3.
	#[serde(rename = "3")] _3 = 0b0011,
	
	/// 4.
	#[serde(rename = "4")] _4 = 0b0100,
	
	/// 5.
	#[serde(rename = "5")] _5 = 0b0101,
	
	/// 6.
	#[serde(rename = "6")] _6 = 0b0110,
	
	/// 7.
	#[serde(rename = "7")] _7 = 0b0111,
	
	/// 8.
	#[serde(rename = "8")] _8 = 0b1101,
	
	/// 9.
	#[serde(rename = "9")] _9 = 0b1110,
}
