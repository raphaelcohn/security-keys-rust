// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Some units are variable.
/// Most units are fixed:-
///
/// * Time: seconds.
/// * Current: ampere.
/// * Luminous intensity: candela.
/// * Reserved: none.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Unit
{
	system: System,
	
	length_or_angle: Option<Exponent>,

	mass: Option<Exponent>,

	time: Option<Exponent>,

	temperature: Option<Exponent>,

	current: Option<Exponent>,
	
	luminous_intensity: Option<Exponent>,

	reserved: Option<Exponent>,
}

impl Debug for Unit
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		let (length_or_angle, mass, time, temperature, current, luminous_intensity, reserved) = self.system.units();
		
		#[inline(always)]
		fn write_exponent<U: Units>(f: &mut Formatter, exponent: Exponent, unit: CommonUnits<U>) -> fmt::Result
		{
			write!(f, "{}{}", unit.to_short_format(), exponent.to_str())
		}
		
		if let Some(exponent) = self.length_or_angle
		{
			write_exponent(f, exponent, length_or_angle)?
		}
		
		if let Some(exponent) = self.mass
		{
			write_exponent(f, exponent, mass)?
		}
		
		if let Some(exponent) = self.time
		{
			write_exponent(f, exponent, time)?
		}
		
		if let Some(exponent) = self.temperature
		{
			write_exponent(f, exponent, temperature)?
		}
		
		if let Some(exponent) = self.current
		{
			write_exponent(f, exponent, current)?
		}
		
		if let Some(exponent) = self.luminous_intensity
		{
			write_exponent(f, exponent, luminous_intensity)?
		}
		
		if let Some(exponent) = self.reserved
		{
			write_exponent(f, exponent, reserved)?
		}
		
		Ok(())
	}
}

impl Unit
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn system(&self) -> System
	{
		self.system
	}
	
	#[inline(always)]
	pub(super) fn parse(data: u32) -> Self
	{
		Self
		{
			system: System::parse((data & 0b1111) as u8),
			
			length_or_angle: Exponent::extract_nibble_and_parse::<1>(data),
			
			mass: Exponent::extract_nibble_and_parse::<2>(data),
			
			time: Exponent::extract_nibble_and_parse::<3>(data),
			
			temperature: Exponent::extract_nibble_and_parse::<4>(data),
			
			current: Exponent::extract_nibble_and_parse::<5>(data),
			
			luminous_intensity: Exponent::extract_nibble_and_parse::<6>(data),
			
			reserved: Exponent::extract_nibble_and_parse::<7>(data),
		}
	}
}
