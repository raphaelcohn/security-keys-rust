// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


struct SimpleMapSerializer<'a, W: Write>
{
	parent: &'a mut SimpleSerializer<W>,
}

impl<'a, W: Write> Deref for SimpleMapSerializer<'a, W>
{
	type Target = SimpleSerializer<W>;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		self.parent
	}
}

impl<'a, W: Write> DerefMut for SimpleMapSerializer<'a, W>
{
	#[inline(always)]
	fn deref_mut(&mut self) -> &mut Self::Target
	{
		self.parent
	}
}

impl<'a, W: Write> SerializeMap for SimpleMapSerializer<'a, W>
{
	type Ok = ();
	
	type Error = SimpleSerializerError;
	
	#[inline(always)]
	fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Self::Error>
	{
		self.write_identation()?;
		self.serialize_borrow_checker_hack(key)?;
		self.serialize_bytes(b": ")?;
		Ok(())
	}
	
	#[inline(always)]
	fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error>
	{
		self.serialize_borrow_checker_hack(value)
	}
	
	#[inline(always)]
	fn end(mut self) -> Result<(), Self::Error>
	{
		self.decrease_indentation();
		self.write_identation()?;
		self.serialize_bytes(b"}")?;
		Ok(())
	}
}

impl<'a, W: Write> SimpleMapSerializer<'a, W>
{
	#[inline(always)]
	fn new(parent: &'a mut SimpleSerializer<W>) -> Self
	{
		Self
		{
			parent
		}
	}
}
