// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


struct SimpleStructSerializer<'a, W: Write>
{
	parent: &'a mut SimpleSerializer<W>,
}

impl<'a, W: Write> Deref for SimpleStructSerializer<'a, W>
{
	type Target = SimpleSerializer<W>;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		self.parent
	}
}

impl<'a, W: Write> DerefMut for SimpleStructSerializer<'a, W>
{
	#[inline(always)]
	fn deref_mut(&mut self) -> &mut Self::Target
	{
		self.parent
	}
}

impl<'a, W: Write> SerializeStruct for SimpleStructSerializer<'a, W>
{
	type Ok = ();
	
	type Error = SimpleSerializerError;
	
	#[inline(always)]
	fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
	{
		self.serialize_value(key, value)
	}
	
	#[inline(always)]
	fn end(self) -> Result<(), Self::Error>
	{
		self.finish()
	}
}

impl<'a, W: Write> SerializeStructVariant for SimpleStructSerializer<'a, W>
{
	type Ok = ();
	
	type Error = SimpleSerializerError;
	
	#[inline(always)]
	fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
	{
		self.serialize_value(key, value)
	}
	
	#[inline(always)]
	fn end(self) -> Result<(), Self::Error>
	{
		self.finish()
	}
}

impl<'a, W: Write> SimpleStructSerializer<'a, W>
{
	#[inline(always)]
	fn new(parent: &'a mut SimpleSerializer<W>) -> Self
	{
		Self
		{
			parent,
		}
	}
	
	#[inline(always)]
	fn serialize_value<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), SimpleSerializerError>
	{
		self.write_identation()?;
		self.serialize_bytes(key.as_bytes())?;
		self.serialize_bytes(b": ")?;
		self.serialize_borrow_checker_hack(value)?;
		Ok(())
	}
	
	#[inline(always)]
	fn finish(mut self) -> Result<(), SimpleSerializerError>
	{
		self.decrease_indentation();
		self.write_identation()?;
		self.serialize_bytes(b"}")?;
		Ok(())
	}
}
