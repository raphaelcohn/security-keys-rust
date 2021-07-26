// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct ConstructedValues<'a>(Vec<TagLengthValue<'a>>);

impl<'a> Deref for ConstructedValues<'a>
{
	type Target = [TagLengthValue<'a>];
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		self.0.deref()
	}
}

impl<'a> ConstructedValues<'a>
{
	#[inline(always)]
	pub(crate) fn find_first(&self, tag: Tag) -> Option<&Values<'a>>
	{
		for tag_length_value in &self.0
		{
			if tag_length_value.has_tag(tag)
			{
				return Some(&tag_length_value.values)
			}
		}
		None
	}
	
	pub(crate) fn find_first_recursively_depth_first(&self, tag: Tag) -> Option<&Values<'a>>
	{
		for tag_length_value in &self.0
		{
			if let Some(values) = tag_length_value.find_first_recursively_depth_first(tag)
			{
				return Some(values)
			}
		}
		None
	}
	
	#[inline(always)]
	pub(crate) fn into_owned(self) -> Result<ConstructedValues<'static>, TryReserveError>
	{
		let mut constructed_values = Vec::new_with_capacity(self.len())?;
		for original in self.0
		{
			constructed_values.push(original.into_owned()?)
		}
		Ok(Self(constructed_values))
	}
	
	#[inline(always)]
	pub(crate) fn parse_borrowed(value: &'a [u8]) -> Result<Self, TagLengthValueParseError>
	{
		Self::parse(value, false)
	}
	
	#[inline(always)]
	pub(crate) fn parse_owned(value: &'a [u8]) -> Result<ConstructedValues<'static>, TagLengthValueParseError>
	{
		let this = Self::parse(value, true)?;
		unsafe { transmute(this) }
	}
	
	#[inline(always)]
	fn parse(value: &'a [u8], owned: bool) -> Result<Self, TagLengthValueParseError>
	{
		let mut input = Input(value);
		let constructed_values = Vec::new();
		loop
		{
			if let Some(tag_length_value) = TagLengthValue::parse(&mut input, owned)?
			{
				constructed_values.try_reserve_exact(1)?;
				constructed_values.push(tag_length_value);
			}
			else
			{
				break
			}
		}
		Ok(Self(constructed_values))
	}
}
