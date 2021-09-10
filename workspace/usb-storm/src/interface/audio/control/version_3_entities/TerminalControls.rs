// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Terminal controls.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalControls
{
	insertion: Control,
	
	overload: Control,
	
	underflow: Control,
	
	overflow: Control,
}

impl TerminalControls
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn insertion(self) -> Control
	{
		self.insertion
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn overload(self) -> Control
	{
		self.overload
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn underflow(self) -> Control
	{
		self.underflow
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn overflow(self) -> Control
	{
		self.overflow
	}
	
	#[inline(always)]
	fn parse<const index: usize>(entity_body: &[u8]) -> Result<Self, TerminalControlsParseError>
	{
		use TerminalControlsParseError::*;
		
		let bmControls = entity_body.u32(entity_index::<index>());
		
		Ok
		(
			Self
			{
				insertion: Control::parse_u32(bmControls, 0, InsertionControlInvalid)?,
				
				overload: Control::parse_u32(bmControls, 1, OverloadControlInvalid)?,
				
				underflow: Control::parse_u32(bmControls, 2, UnderflowControlInvalid)?,
				
				overflow: Control::parse_u32(bmControls, 3, OverflowControlInvalid)?,
			}
		)
	}
}
