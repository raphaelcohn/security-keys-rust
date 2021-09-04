// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Hub packet header decode latency.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum PacketHeaderDecodeLatency
{
	/// Much less than 0·1μs.
	MuchLessThan_0·1μs,
	
	/// 0·1μs.
	#[serde(rename = "0·1μs")] _0·1μs,
	
	/// 0·1μs.
	#[serde(rename = "0·2μs")] _0·2μs,
	
	/// 0·1μs.
	#[serde(rename = "0·3μs")] _0·3μs,
	
	/// 0·1μs.
	#[serde(rename = "0·4μs")] _0·4μs,
	
	/// 0·1μs.
	#[serde(rename = "0·5μs")] _0·5μs,
	
	/// 0·1μs.
	#[serde(rename = "0·6μs")] _0·6μs,
	
	/// 0·1μs.
	#[serde(rename = "0·7μs")] _0·7μs,
	
	/// 0·1μs.
	#[serde(rename = "0·8μs")] _0·8μs,
	
	/// 0·1μs.
	#[serde(rename = "0·9μs")] _0·9μs,
	
	/// 0·1μs.
	#[serde(rename = "1·0μs")] _1·0μs,
	
	#[allow(missing_docs)]
	Reserved(u8),
}

impl PacketHeaderDecodeLatency
{
	fn parse(value: u8) -> Self
	{
		use PacketHeaderDecodeLatency::*;
		
		match value
		{
			0x00 => MuchLessThan_0·1μs,
			
			0x01 => _0·1μs,
			
			0x02 => _0·2μs,
			
			0x03 => _0·3μs,
			
			0x04 => _0·4μs,
			
			0x05 => _0·5μs,
			
			0x06 => _0·6μs,
			
			0x07 => _0·7μs,
			
			0x08 => _0·8μs,
			
			0x09 => _0·9μs,
			
			0x0A => _1·0μs,
			
			0x0B ..= 0xFF => Reserved(value)
		}
	}
}
