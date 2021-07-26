// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum Values<'a>
{
	Primitive(Cow<'a, [u8]>),

	Constructed(ConstructedValues<'a>),
}

impl<'a> Values<'a>
{
	#[inline(always)]
	fn into_owned(self) -> Result<Values<'static>, TryReserveError>
	{
		use self::Values::*;
		
		Ok
		(
			match self
			{
				Primitive(primitive) => Primitive(Cow::Owned(Self::primitive_slice_to_owned(primitive.as_ref())?)),
				
				Constructed(constructed_values) => Constructed(constructed_values.into_owned()?),
			}
		)
	}
	
	fn parse(input: &mut Input<'a>, owned: bool, tag_type: TagType, length: u16) -> Result<Self, TagLengthValueParseError>
	{
		let value = input.take_bytes_error(length as usize, || TagLengthValueParseError::Value { length })?;
		
		use self::TagType::*;
		
		let this = match tag_type
		{
			Primitive => Values::Primitive
			(
				if owned
				{
					Cow::Owned(Self::primitive_slice_to_owned(value.as_ref())?)
				}
				else
				{
					Cow::Borrowed(value)
				}
			),
			
			Constructed => Values::Constructed(ConstructedValues::parse(value, owned)?)
		};
		Ok(this)
	}
	
	#[inline(always)]
	fn primitive_slice_to_owned(slice: &'a [u8]) -> Result<Vec<u8>, TryReserveError>
	{
		let mut owned = Vec::new_with_capacity(slice.len())?;
		owned.extend_from_slice(slice);
		Ok(owned)
	}
}
