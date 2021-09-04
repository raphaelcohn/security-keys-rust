// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Tries to clone a collection.
pub trait TryClone: Sized
{
	/// Tries to clone a collection.
	fn try_clone(&self) -> Result<Self, TryReserveError>;
}

impl<TC: TryClone> TryClone for Vec<TC>
{
	#[inline(always)]
	fn try_clone(&self) -> Result<Self, TryReserveError>
	{
		let length = self.len();
		let mut clone = Vec::new_with_capacity(length)?;
		for index in 0 ..length
		{
			clone.push_unchecked(self.get_unchecked_safe(index).try_clone()?)
		}
		Ok(clone)
	}
}

impl<TC: TryClone> TryClone for Option<TC>
{
	#[inline(always)]
	fn try_clone(&self) -> Result<Self, TryReserveError>
	{
		match self
		{
			None => Ok(None),
			
			Some(inner) => Ok(Some(inner.try_clone()?)),
		}
	}
}

impl TryClone for u32
{
	#[inline(always)]
	fn try_clone(&self) -> Result<Self, TryReserveError>
	{
		Ok(*self)
	}
}

impl TryClone for u8
{
	#[inline(always)]
	fn try_clone(&self) -> Result<Self, TryReserveError>
	{
		Ok(*self)
	}
}
