// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


struct SimpleSequenceSerializer<'a, W: Write>
{
	parent: &'a mut SimpleSerializer<W>,
	
	end_byte: u8,
}

impl<'a, W: Write> Deref for SimpleSequenceSerializer<'a, W>
{
	type Target = SimpleSerializer<W>;
	
	#[inline(always)]
	fn deref(&self) -> &Self::Target
	{
		self.parent
	}
}

impl<'a, W: Write> DerefMut for SimpleSequenceSerializer<'a, W>
{
	#[inline(always)]
	fn deref_mut(&mut self) -> &mut Self::Target
	{
		self.parent
	}
}

impl<'a, W: Write> SerializeSeq for SimpleSequenceSerializer<'a, W>
{
	type Ok = ();
	
	type Error = SimpleSerializerError;
	
	#[inline(always)]
	fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error>
	{
		self.serialize_value(value)
	}
	
	#[inline(always)]
	fn end(self) -> Result<(), Self::Error>
	{
		self.finish()
	}
}

impl<'a, W: Write> SerializeTuple for SimpleSequenceSerializer<'a, W>
{
	type Ok = ();
	
	type Error = SimpleSerializerError;
	
	#[inline(always)]
	fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error>
	{
		self.serialize_value(value)
	}
	
	#[inline(always)]
	fn end(self) -> Result<(), Self::Error>
	{
		self.finish()
	}
}

impl<'a, W: Write> SerializeTupleStruct for SimpleSequenceSerializer<'a, W>
{
	type Ok = ();
	
	type Error = SimpleSerializerError;
	
	#[inline(always)]
	fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error>
	{
		self.serialize_value(value)
	}
	
	#[inline(always)]
	fn end(self) -> Result<(), Self::Error>
	{
		self.finish()
	}
}

impl<'a, W: Write> SerializeTupleVariant for SimpleSequenceSerializer<'a, W>
{
	type Ok = ();
	
	type Error = SimpleSerializerError;
	
	#[inline(always)]
	fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error>
	{
		self.serialize_value(value)
	}
	
	#[inline(always)]
	fn end(self) -> Result<(), Self::Error>
	{
		self.finish()
	}
}

impl<'a, W: Write> SimpleSequenceSerializer<'a, W>
{
	#[inline(always)]
	fn new(parent: &'a mut SimpleSerializer<W>, end_byte: u8) -> Self
	{
		Self
		{
			parent,
		
			end_byte,
		}
	}
	
	#[inline(always)]
	fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SimpleSerializerError>
	{
		self.write_identation()?;
		self.serialize_borrow_checker_hack(value)?;
		Ok(())
	}
	
	#[inline(always)]
	fn finish(mut self) -> Result<(), SimpleSerializerError>
	{
		self.decrease_indentation();
		self.write_identation()?;
		let end_byte = self.end_byte;
		self.serialize_bytes(&[end_byte])?;
		Ok(())
	}
}
