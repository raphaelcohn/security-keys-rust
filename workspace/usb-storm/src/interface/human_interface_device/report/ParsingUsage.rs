// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Usage.
#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct ParsingUsage
{
	data: u32,
	
	data_width: DataWidth,
}

impl TryClone for ParsingUsage
{
	#[inline(always)]
	fn try_clone(&self) -> Result<Self, TryReserveError>
	{
		Ok(*self)
	}
}

impl ParsingUsage
{
	#[inline(always)]
	fn next(self) -> Self
	{
		Self
		{
			data: self.data + 1,
		
			data_width: self.data_width,
		}
	}
	
	#[inline(always)]
	fn finish(self, usage_page: UsagePage) -> Usage
	{
		Usage
		{
			page: if self.data_width == DataWidth::ThirtyTwoBit
			{
				(self.data >> 16) as u16
			}
			else
			{
				usage_page
			},
			
			identifier: self.data as u16,
		}
	}
	
	#[inline(always)]
	fn parse(data: u32, data_width: DataWidth) -> Self
	{
		Self
		{
			data,
		
			data_width,
		}
	}
}
