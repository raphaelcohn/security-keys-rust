// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A signed value indicating the power of ten to scale 'Unit' by.
///
/// Parsing this has a very messy and broken history of misunderstanding.
///
/// Summarising from a Linux commit:-
/// * This value should just be a signed integer value.
/// * However several significant sources deviate from this:-
/// 	* the offical [HID Descriptor Tool](https://www.usb.org/document-library/hid-descriptor-tool).
/// 	* Books such as "USB Complete".
/// 	* Microsoft's hardware design guides.
/// * That said, some devices do correctly set this.
#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[repr(transparent)]
pub struct UnitExponent(i32);

impl Display for UnitExponent
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		write!(f, "{}", self.try_to_string().map_err(|_| fmt::Error)?)
	}
}

impl UnitExponent
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn scalar(self) -> f64
	{
		10f64.powi(self.0 as i32)
	}
	
	#[inline(always)]
	fn try_to_string(self) -> Result<String, TryReserveError>
	{
		let mut string = String::new();
		let _ = self.0.performant_to_decimal_utf8_string::<SuperscriptLatinNumberAsDecimalStringFormat, _>(&mut string)?;
		Ok(string)
	}
	
	/// This logic tries to identify values that use the full-width of the exponent, vs those that mistakenly (but commonly) only use a nibble.
	#[inline(always)]
	pub(super) fn parse(data: u32, data_width: DataWidth) -> Self
	{
		use DataWidth::*;
		
		match data_width
		{
			Widthless =>
			{
				debug_assert_eq!(data, 0);
				Self(0)
			},
			
			EightBit =>
			{
				if (data & 0b1111_0000) != 0
				{
					Self(data as i32)
				}
				else
				{
					Self(parse_exponent_nibble((data & 0b0000_1111) as u8) as i32)
				}
			}
			
			_ => Self(data as i32)
		}
		
	}
}
