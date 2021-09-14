// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A value of a power of ten between -8 and 7 inclusive.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[repr(transparent)]
pub struct Exponent(NonZeroI8);

impl Display for Exponent
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		write!(f, "{}", self.to_str())
	}
}

impl Exponent
{
	const NibbleMask: u8 = 0b1111;
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn scalar(self) -> f64
	{
		10f64.powi(self.0.get() as i32)
	}
	
	#[inline(always)]
	fn to_str(self) -> &'static str
	{
		match self.0.get()
		{
			7 => "⁷",
			
			6 => "⁶",
			
			5 => "⁵",
			
			4 => "⁴",
			
			3 => "³",
			
			2 => "²",
			
			1 => "¹",
			
			-1 => "⁻¹",
			
			-2 => "⁻²",
			
			-3 => "⁻³",
			
			-4 => "⁻⁴",
			
			-5 => "⁻⁵",
			
			-6 => "⁻⁶",
			
			-7 => "⁻⁷",
			
			-8 => "⁻⁸",
			
			_ => unreachable!(),
		}
	}
	
	#[inline(always)]
	fn extract_nibble_and_parse<const nibble_index: u8>(data: u32) -> Option<Self>
	{
		Self::parse(Self::extract_nibble::<nibble_index>(data))
	}
	
	#[inline(always)]
	fn extract_nibble<const nibble_index: u8>(data: u32) -> u8
	{
		let shift = (nibble_index * 4) as u32;
		
		((data >> shift) & (Self::NibbleMask as u32)) as u8
	}
	
	#[inline(always)]
	fn parse(exponent_nibble: u4) -> Option<Self>
	{
		let exponent = parse_exponent_nibble(exponent_nibble);
		if likely!(exponent == 0)
		{
			None
		}
		else
		{
			Some(Self(new_non_zero_i8(exponent as i8)))
		}
	}
}
