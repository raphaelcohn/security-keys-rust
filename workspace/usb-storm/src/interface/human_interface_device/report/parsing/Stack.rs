// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(transparent)]
struct Stack<V, E: error::Error + Into<ReportParseError> + From<StackError>>(Vec<V>, PhantomData<E>);

impl<V, E: error::Error + Into<ReportParseError> + From<StackError>> Deref for Stack<V, E>
{
	type Target = Vec<V>;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		&self.0
	}
}

impl<V, E: error::Error + Into<ReportParseError> + From<StackError>> DerefMut for Stack<V, E>
{
	#[inline(always)]
	fn deref_mut(&mut self) -> &mut Self::Target
	{
		&mut self.0
	}
}

impl<V, E: error::Error + Into<ReportParseError> + From<StackError>> Stack<V, E>
{
	#[inline(always)]
	fn new(top: V, maximum_depth: NonZeroU8) -> Result<Self, ReportParseError>
	{
		let mut vec = Vec::new_with_capacity(maximum_depth).map_err(|cause| E::from(StackError::CouldNotAllocateStack(cause)).into())?;
		vec.push_unchecked(top);
		Ok(Self(vec, PhantomData))
	}
	
	#[inline(always)]
	fn push_value(&mut self, value: V) -> Result<(), ReportParseError>
	{
		if unlikely!(self.len() == self.capacity())
		{
			return Err(E::from(StackError::StackOverflow).into())
		}
		self.push_unchecked(value);
		Ok(())
	}
	
	#[inline(always)]
	fn current(&mut self) -> &mut V
	{
		debug_assert_ne!(self.len(), 0, "Should not be empty for current");
		self.last_mut().unwrap()
	}
}

impl Stack<CollectionMainItem, CollectionParseError>
{
	#[inline(always)]
	fn consume(&mut self) -> Result<CollectionMainItem, ReportParseError>
	{
		self.guard_consume()?;
		
		let value = unsafe
		{
			self.set_len(0);
			ptr::read(self.as_ptr())
		};
		Ok(value)
	}
	
	#[inline(always)]
	fn guard_consume(&mut self) -> Result<(), CollectionParseError>
	{
		let length = self.len();
		debug_assert_ne!(length, 0, "Should not be empty for consume");
		
		if unlikely!(length > 1)
		{
			return Err(CollectionParseError::UnclosedCollection)
		}
		
		Ok(())
	}
}
