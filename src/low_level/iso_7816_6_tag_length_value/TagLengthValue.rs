// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A BER TLV (tag-length-value) as defiend by ISO 8825.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct TagLengthValue<'a>
{
	tag: Tag,

	values: Values<'a>,
}

impl<'a> TagLengthValue<'a>
{
	#[inline(always)]
	fn has_tag(&self, tag: Tag) -> bool
	{
		self.tag == tag
	}
	
	#[inline(always)]
	fn find_first_recursively_depth_first(&self, tag: Tag) -> Option<&Values<'a>>
	{
		if self.has_tag(tag)
		{
			return Some(&self.values)
		}
		
		use self::Values::*;
		
		match self.values
		{
			Primitive(_) => None,
			
			Constructed(ref constructed_values) => constructed_values.find_first_recursively_depth_first(tag)
		}
	}
	
	#[inline(always)]
	fn into_owned(self) -> Result<TagLengthValue<'static>, TryReserveError>
	{
		Ok
		(
			Self
			{
				tag: self.tag,
			
				values: self.values.into_owned()?,
			}
		)
	}
	
	fn parse(input: &mut Input, owned: bool) -> Result<Option<Self>, TagLengthValueParseError>
	{
		let leading_tag_byte = match Self::parse_ber_tag_length_value_space(input)
		{
			None => return Ok(None),
			
			Some(leading_tag_byte) => leading_tag_byte,
		};
		let (tag, tag_type) = Tag::parse(input, leading_tag_byte)?;
		let length = Self::parse_length(input)?;
		let values = Values::parse(input, owned, tag_type, length)?;
		Ok
		(
			Some
			(
				Self
				{
					tag,
				
					values,
				}
			)
		)
	}
	
	/// See [ISO 7816-4 Annex D, Section D.1 BER-TLV data object](https://cardwerk.com/iso7816-4-annex-d-use-of-basic-encoding-rules-asn-1/)
	/// Values of 0x00 and 0xFF are used as leading and trailing space as well as separators between Tag-Length-Values, hence there may be a need to 'soak' up trailing space.
	#[inline(always)]
	fn parse_ber_tag_length_value_space(input: &mut Input) -> Option<u8>
	{
		loop
		{
			match input.take()
			{
				None => return None,
				
				Some(byte) => match byte
				{
					0x00 => continue,
					
					0xFF => continue,
					
					_ => return Some(byte),
				}
			}
		}
	}
	
	/// See [ISO 7816-4 Annex D, Section D.3 Length Field](https://cardwerk.com/iso7816-4-annex-d-use-of-basic-encoding-rules-asn-1/).
	#[inline(always)]
	fn parse_length(input : &mut Input) -> Result<u16, TagLengthValueParseError>
	{
		use self::TagLengthValueParseError::*;
		
		let length_first_byte = input.take_error(OutOfDataForLengthFirstByte)?;
		
		const Bottom7Bits: u8 = 0b0111_1111;
		let length_value = length_first_byte & Bottom7Bits;
		
		let is_short_form = (length_first_byte & 0b1000_000) == 0;
		let length = if is_short_form
		{
			length_value as u16
		}
		else
		{
			match length_value
			{
				1 => input.take_error(OutOfDataForLongLengthOf1)? as u16,
				
				2 =>
				{
					let top = input.take_error(OutOfDataForLongLengthOf2)? as u16;
					let bottom = input.take_error(OutOfDataForLongLengthOf2)? as u16;
					(top << 8) | bottom
				}
				
				_ => return Err(LengthFieldEncodesValueGreaterThan65535),
			}
		};
		
		Ok(length)
	}
}
