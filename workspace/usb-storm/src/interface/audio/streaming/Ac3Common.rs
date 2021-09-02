// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// AC-3 common details.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ac3Common
{
	internal_dynamic_range_control: InternalDynamicRangeControl,
	
	bit_stream_id_modes: WrappedBitFlags<BitStreamIdMode>,
	
	rf_mode: bool,
	
	line_mode: bool,
	
	custom0_mode: bool,
	
	custom1_mode: bool,
}

impl Ac3Common
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn internal_dynamic_range_control(&self) -> InternalDynamicRangeControl
	{
		self.internal_dynamic_range_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn bit_stream_id_modes(&self) -> WrappedBitFlags<BitStreamIdMode>
	{
		self.bit_stream_id_modes
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn rf_mode(&self) -> bool
	{
		self.rf_mode
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn line_mode(&self) -> bool
	{
		self.line_mode
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn custom0_mode(&self) -> bool
	{
		self.custom0_mode
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn custom1_mode(&self) -> bool
	{
		self.custom1_mode
	}
	
	#[inline(always)]
	fn parse<E: error::Error>(descriptor_body: &[u8], error: E) -> Result<Self, E>
	{
		let bmAC3Features = descriptor_body.u8(descriptor_index::<9>());
		
		Ok
		(
			Self
			{
				internal_dynamic_range_control: InternalDynamicRangeControl::from_2_bits(bmAC3Features >> 4),
				
				bit_stream_id_modes:
				{
					let bmBSID = descriptor_body.u32(descriptor_index::<5>());
					const Lower9Modes: u32 = 0b1_1111_1111;
					if (bmBSID & Lower9Modes) != Lower9Modes
					{
						return Err(error)
					}
					WrappedBitFlags::from_bits_unchecked(bmBSID)
				},
				
				rf_mode: (bmAC3Features & 0b0001) != 0,
				
				line_mode: (bmAC3Features & 0b0010) != 0,
				
				custom0_mode: (bmAC3Features & 0b0100) != 0,
				
				custom1_mode: (bmAC3Features & 0b1000) != 0
			}
		)
	}
}
