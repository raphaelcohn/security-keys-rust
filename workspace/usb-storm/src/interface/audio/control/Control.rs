// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A control.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u8)]
pub enum Control
{
	#[allow(missing_docs)]
	NotPresent = 0b00,
	
	#[allow(missing_docs)]
	ReadOnly = 0b01,
	
	#[allow(missing_docs)]
	HostProgrammable = 0b11,
}

impl Control
{
	#[inline(always)]
	fn parse_u8<E: error::Error>(bitmap: u8, control_index: u8, invalid_control_error: E) -> Result<Control, E>
	{
		debug_assert!(control_index < 4);
		Self::parse_u16(bitmap as u16, control_index as u16, invalid_control_error)
	}
	
	#[inline(always)]
	fn parse_u16<E: error::Error>(bitmap: u16, control_index: u16, invalid_control_error: E) -> Result<Control, E>
	{
		debug_assert!(control_index < 8);
		Self::parse_u32(bitmap as u32, control_index as u32, invalid_control_error)
	}
	
	#[inline(always)]
	fn parse_u32<E: error::Error>(bitmap: u32, control_index: u32, invalid_control_error: E) -> Result<Control, E>
	{
		debug_assert!(control_index < 16);
		use Control::*;
		let shift = control_index * 2;
		match (bitmap >> shift) & 0b11
		{
			0b00 => Ok(NotPresent),
			
			0b01 => Ok(ReadOnly),
			
			0b10 => Err(invalid_control_error),
			
			0b11 => Ok(HostProgrammable),
			
			_ => unreachable!(),
		}
	}
}
