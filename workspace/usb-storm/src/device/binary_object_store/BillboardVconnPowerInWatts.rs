// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Billboard Vconn power in watts.
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u8)]
pub enum BillboardVconnPowerInWatts
{
	/// 1W.
	_1 = 0b000,
	
	/// 1·5W.
	_1·5 = 0b001,
	
	/// 2W.
	_2 = 0b010,
	
	/// 3W.
	_3 = 0b011,
	
	/// 4W.
	_4 = 0b100,
	
	/// 5W.
	_5 = 0b101,
	
	/// 6W.
	_6 = 0b110,

	/// Reserved.
	Reserved = 0b111,
}

impl BillboardVconnPowerInWatts
{
	#[inline(always)]
	fn parse(device_capability_bytes: &[u8]) -> Option<Self>
	{
		let bits = device_capability_bytes.u16(capability_descriptor_index::<6>());
		if (bits & 0b1000_0000_0000_0000) != 0
		{
			None
		}
		else
		{
			Some(unsafe { transmute((bits & 0b111) as u8) })
		}
	}
}
