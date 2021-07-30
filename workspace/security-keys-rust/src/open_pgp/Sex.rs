// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// Sex (gender).
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum Sex
{
	/// Not known.
	NotKnown = 0x30,

	/// Male.
	Male = 0x31,

	/// Female.
	Female = 0x32,

	/// Not applicable.
	NotApplicable = 0x39,
}

impl From<Sex> for Cow<'static, [u8]>
{
	#[inline(always)]
	fn from(value: Sex) -> Cow<'static, [u8]>
	{
		Cow::Borrowed(value.into())
	}
}

impl Into<&'static [u8]> for Sex
{
	#[inline(always)]
	fn into(self) -> &'static [u8]
	{
		let into: &'static [u8; 1] = self.into();
		into
	}
}

impl Into<&'static [u8; 1]> for Sex
{
	#[inline(always)]
	fn into(self) -> &'static [u8; 1]
	{
		use Sex::*;
		
		match self
		{
			NotKnown =>
			{
				static V: [u8; 1] = [NotKnown as u8];
				&V
			}
			
			Male =>
			{
				static V: [u8; 1] = [Male as u8];
				&V
			}
			
			Female =>
			{
				static V: [u8; 1] = [Female as u8];
				&V
			}
			
			NotApplicable =>
			{
				static V: [u8; 1] = [NotApplicable as u8];
				&V
			}
		}
	}
}
