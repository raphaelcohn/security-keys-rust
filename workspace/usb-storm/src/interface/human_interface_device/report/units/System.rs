// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// System.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum System
{
	/// None.
	None,
	
	/// Defined.
	Defined(LinearOrRotation, SystemOfUnits),
	
	/// A value from 0x05 to 0x0E inclusive.
	Reserved(u4),
	
	/// Vendor-defined.
	VendorDefined,
}

impl System
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn units(self) -> (CommonUnits<LengthOrAngleUnits>, CommonUnits<MassUnits>, CommonUnits<Second>, CommonUnits<TemperatureUnits>, CommonUnits<Ampere>, CommonUnits<Candela>, CommonUnits<ReservedUnits>)
	{
		use CommonUnits::*;
		use LinearOrRotation::*;
		use SystemOfUnits::*;
		use LengthOrAngleUnits::*;
		use MassUnits::*;
		use TemperatureUnits::*;
		
		#[inline(always)]
		fn centimeter_gram_second(length_or_angle_units: LengthOrAngleUnits) -> (CommonUnits<LengthOrAngleUnits>, CommonUnits<MassUnits>, CommonUnits<Second>, CommonUnits<TemperatureUnits>, CommonUnits<Ampere>, CommonUnits<Candela>, CommonUnits<ReservedUnits>)
		{
			defined(length_or_angle_units, Gram, Celsius)
		}
		
		#[inline(always)]
		fn imperial(length_or_angle_units: LengthOrAngleUnits) -> (CommonUnits<LengthOrAngleUnits>, CommonUnits<MassUnits>, CommonUnits<Second>, CommonUnits<TemperatureUnits>, CommonUnits<Ampere>, CommonUnits<Candela>, CommonUnits<ReservedUnits>)
		{
			defined(length_or_angle_units, Slug, Fahrenheit)
		}
		
		#[inline(always)]
		fn defined(length_or_angle_units: LengthOrAngleUnits, mass_units: MassUnits, temperature_units: TemperatureUnits) -> (CommonUnits<LengthOrAngleUnits>, CommonUnits<MassUnits>, CommonUnits<Second>, CommonUnits<TemperatureUnits>, CommonUnits<Ampere>, CommonUnits<Candela>, CommonUnits<ReservedUnits>)
		{
			(Defined(length_or_angle_units), Defined(mass_units), Defined(Second), Defined(temperature_units), Defined(Ampere), Defined(Candela), Defined(ReservedUnits))
		}
		
		macro_rules! identical
		{
			($undefined: ident) =>
			{
				($undefined, $undefined, $undefined, $undefined, $undefined, $undefined, $undefined)
			}
		}
		
		match self
		{
			System::None => identical!(None),
			
			System::Defined(Linear, CentimeterGramSecond) => centimeter_gram_second(Centimeter),
			
			System::Defined(Rotation, CentimeterGramSecond) => centimeter_gram_second(Radian),
			
			System::Defined(Linear, Imperial) => imperial(Inch),
			
			System::Defined(Rotation, Imperial) => imperial(Degree),
			
			System::Reserved(_) => identical!(Reserved),
			
			System::VendorDefined => identical!(VendorDefined),
		}
	}
	
	#[inline(always)]
	fn parse(lower_nibble: u8) -> Self
	{
		use LinearOrRotation::*;
		use SystemOfUnits::*;
		use System::*;
		match lower_nibble
		{
			0x00 => None,
			
			0x01 => Defined(Linear, CentimeterGramSecond),
			
			0x02 => Defined(Rotation, CentimeterGramSecond),
			
			0x03 => Defined(Linear, Imperial),
			
			0x04 =>Defined(Rotation, Imperial),
			
			reserved @ 0x05 ..= 0x0E => Reserved(reserved),
			
			0x0F => VendorDefined,
			
			_ => unreachable!("Should be a nibble"),
		}
	}
}
