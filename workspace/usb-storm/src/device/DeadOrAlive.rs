// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Is this device now dead or alive?
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeadOrAlive<T>
{
	/// It is now dead.
	Dead,

	/// It is still alive.
	Alive(T),
}

impl<T> DeadOrAlive<T>
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn as_ref(&self) -> DeadOrAlive<&T>
	{
		match self
		{
			Dead => Dead,
			
			Alive(u) => Alive(u)
		}
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn map<U>(self, alive: impl FnOnce(T) -> U) -> DeadOrAlive<U>
	{
		match self
		{
			Dead => Dead,
			
			Alive(u) => Alive(alive(u))
		}
	}
}
