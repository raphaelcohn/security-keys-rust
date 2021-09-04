// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct Stack<V>(Vec<V>);

impl<V> Stack<V>
{
	#[inline(always)]
	fn new(value: V) -> Result<Self, ReportParseError>
	{
		let mut this = Self(Vec::new());
		this.push_value(value)?;
		Ok(this)
	}
	
	#[inline(always)]
	fn push_value(&mut self, value: V) -> Result<(), ReportParseError>
	{
		self.0.try_push(value).map_err(ReportParseError::OutOfStackMemory)
	}
	
	#[inline(always)]
	fn pop(&mut self) -> Option<V>
	{
		self.0.pop()
	}
	
	#[inline(always)]
	fn current(&mut self) -> &mut V
	{
		debug_assert_ne!(self.0.len(), 0, "Should not be empty for current");
		self.0.last_mut().unwrap()
	}
	
	#[inline(always)]
	fn guard_consume(&mut self) -> Result<(), ReportParseError>
	{
		let length = self.0.len();
		debug_assert_ne!(length, 0, "Should not be empty for consume");
		
		if unlikely!(length > 1)
		{
			return Err(ReportParseError::OpenNestedStructures)
		}
		
		Ok(())
	}
	
	#[inline(always)]
	fn consume(&mut self) -> Result<V, ReportParseError>
	{
		self.guard_consume()?;
		
		let value = unsafe
		{
			self.0.set_len(0);
			read(self.0.as_ptr())
		};
		Ok(value)
	}
}

impl<V: Default> Stack<V>
{
	#[inline(always)]
	fn push(&mut self) -> Result<(), ReportParseError>
	{
		self.push_value(V::default())
	}
	
	#[inline(always)]
	fn consume_and_replace(&mut self) -> Result<V, ReportParseError>
	{
		self.guard_consume()?;
		
		Ok(take(self.0.get_unchecked_mut_safe(0)))
	}
}

impl Stack<ParsingLocalItems>
{
	#[inline(always)]
	fn try_clone(&self) -> Result<Self, TryReserveError>
	{
		Ok
		(
			Self
			(
				self.0.try_clone()?
			)
		)
	}
}
