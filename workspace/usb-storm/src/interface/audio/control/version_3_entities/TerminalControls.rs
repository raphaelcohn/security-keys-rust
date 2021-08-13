// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Terminal controls.
#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalControls
{
	insertion: u2,
	
	overload: u2,
	
	underflow: u2,
	
	overflow: u2,
}

impl TerminalControls
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn insertion(self) -> u2
	{
		self.insertion
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn overload(self) -> u2
	{
		self.overload
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn underflow(self) -> u2
	{
		self.underflow
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn overflow(self) -> u2
	{
		self.overflow
	}
	
	#[inline(always)]
	fn new<const index: usize>(entity_body: &[u8]) -> Self
	{
		let bmControls = entity_body.u32_unadjusted(entity_index::<index>());
		
		Self
		{
			insertion: (bmControls & 0b11) as u2,
			
			overload: ((bmControls >> 2) & 0b11) as u2,
			
			underflow: ((bmControls >> 4) & 0b11) as u2,
			
			overflow: ((bmControls >> 6) & 0b11) as u2,
		}
	}
}
