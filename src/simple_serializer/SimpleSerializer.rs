// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


struct SimpleSerializer<W: Write>
{
	output: BufWriter<W>,

	indentation: Vec<u8>,
}

impl<'a, W: Write> Serializer for &'a mut SimpleSerializer<W>
{
	type Ok = ();
	
	type Error = SimpleSerializerError;
	
	type SerializeSeq = SimpleSequenceSerializer<'a, W>;
	
	type SerializeTuple = SimpleSequenceSerializer<'a, W>;
	
	type SerializeTupleStruct = SimpleSequenceSerializer<'a, W>;
	
	type SerializeTupleVariant = SimpleSequenceSerializer<'a, W>;
	
	type SerializeMap = SimpleMapSerializer<'a, W>;
	
	type SerializeStruct = SimpleStructSerializer<'a, W>;
	
	type SerializeStructVariant = SimpleStructSerializer<'a, W>;
	
	#[inline(always)]
	fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error>
	{
		self.serialize_bytes(match v
		{
			true => b"true" as &[u8],
			
			false => b"false" as &[u8],
		})
	}
	
	#[inline(always)]
	fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error>
	{
		self.write_integer(v)
	}
	
	#[inline(always)]
	fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error>
	{
		self.write_integer(v)
	}
	
	#[inline(always)]
	fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error>
	{
		self.write_integer(v)
	}
	
	#[inline(always)]
	fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error>
	{
		self.write_integer(v)
	}
	
	#[inline(always)]
	fn serialize_i128(self, v: i128) -> Result<Self::Ok, Self::Error>
	{
		self.write_integer(v)
	}
	
	#[inline(always)]
	fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error>
	{
		self.write_integer(v)
	}
	
	#[inline(always)]
	fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error>
	{
		self.write_integer(v)
	}
	
	#[inline(always)]
	fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error>
	{
		self.write_integer(v)
	}
	
	#[inline(always)]
	fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error>
	{
		self.write_integer(v)
	}
	
	#[inline(always)]
	fn serialize_u128(self, v: u128) -> Result<Self::Ok, Self::Error>
	{
		self.write_integer(v)
	}
	
	#[inline(always)]
	fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error>
    {
		self.write_float(v)
	}
	
	#[inline(always)]
	fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error>
    {
		self.write_float(v)
	}

	#[inline(always)]
	fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error>
    {
		if v.is_control() || v.is_whitespace()
		{
			let bytes = match v
			{
				'\t' => b"\\t",
				
				'\r' => b"\\r",
				
				'\n' => b"\\n",
				
				'\\' => b"\\\\",
				
				'\"' => b"\\\"",
				
				'\'' => b"\\'",
				
				_ =>
				{
					self.serialize_bytes(b"0x")?;
					
					let v: u32 = v as u32;
					let bytes = v.to_be_bytes();
					
					self.write_byte_as_hexadecimal(bytes.get_unchecked_value_safe(0))?;
					self.write_byte_as_hexadecimal(bytes.get_unchecked_value_safe(1))?;
					self.write_byte_as_hexadecimal(bytes.get_unchecked_value_safe(2))?;
					return self.write_byte_as_hexadecimal(bytes.get_unchecked_value_safe(3))
				}
			};
			self.serialize_bytes(bytes)
		}
		else
		{
			const MaximumUtf8Length: usize = 4;
			let mut buffer: [MaybeUninit<u8>; MaximumUtf8Length] = MaybeUninit::uninit_array();
			let string = v.encode_utf8(unsafe { from_raw_parts_mut(buffer.as_mut_ptr() as *mut u8, MaximumUtf8Length) });
			self.serialize_bytes(string.as_bytes())
		}
	}

	fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error>
	{
		for c in v.chars()
		{
			self.serialize_char(c)?;
		}
		Ok(())
	}
	
	#[inline(always)]
	fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error>
	{
		self.output.write_all(v)?;
		Ok(())
	}
	
	#[inline(always)]
	fn serialize_none(self) -> Result<Self::Ok, Self::Error>
	{
		self.serialize_bytes(b"None")
	}
	
	#[inline(always)]
	fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error>
	{
		self.serialize_newtype_struct("Some", value)
	}
	
	#[inline(always)]
	fn serialize_unit(self) -> Result<Self::Ok, Self::Error>
	{
		self.serialize_bytes(b"()")
	}
	
	#[inline(always)]
	fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error>
	{
		self.serialize_unit()
	}
	
	#[inline(always)]
	fn serialize_unit_variant(self, _name: &'static str, _variant_index: u32, variant: &'static str) -> Result<Self::Ok, Self::Error>
	{
		self.serialize_str(variant)
	}
	
	#[inline(always)]
	fn serialize_newtype_struct<T: ?Sized + Serialize>(self, name: &'static str, value: &T) -> Result<Self::Ok, Self::Error>
	{
		self.serialize_bytes(name.as_bytes())?;
		
		self.write_identation()?;
		self.serialize_bytes(b"(")?;
		self.increase_indentation();
		
		self.serialize_borrow_checker_hack(value)?;
		
		self.decrease_indentation();
		self.write_identation()?;
		self.serialize_bytes(b")")
	}
	
	#[inline(always)]
	fn serialize_newtype_variant<T: ?Sized + Serialize>(self, _name: &'static str, _variant_index: u32, variant: &'static str, value: &T) -> Result<Self::Ok, Self::Error>
	{
		self.serialize_newtype_struct(variant, value)
	}
	
	#[inline(always)]
	fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error>
	{
		self.serialize_bytes(b"[")?;
		self.increase_indentation();
		Ok(SimpleSequenceSerializer::new(self, b']'))
	}
	
	#[inline(always)]
	fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error>
	{
		self.serialize_bytes(b"(")?;
		self.increase_indentation();
		Ok(SimpleSequenceSerializer::new(self, b')'))
	}
	
	#[inline(always)]
	fn serialize_tuple_struct(self, name: &'static str, _len: usize) -> Result<Self::SerializeTupleStruct, Self::Error>
	{
		self.serialize_bytes(name.as_bytes())?;
		
		self.write_identation()?;
		self.serialize_bytes(b"(")?;
		self.increase_indentation();
		Ok(SimpleSequenceSerializer::new(self, b')'))
	}
	
	#[inline(always)]
	fn serialize_tuple_variant(self, _name: &'static str, _variant_index: u32, variant: &'static str, _len: usize) -> Result<Self::SerializeTupleVariant, Self::Error>
	{
		self.serialize_bytes(variant.as_bytes())?;
		
		self.write_identation()?;
		self.serialize_bytes(b"(")?;
		self.increase_indentation();
		Ok(SimpleSequenceSerializer::new(self, b')'))
	}
	
	#[inline(always)]
	fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error>
	{
		self.write_identation()?;
		self.serialize_bytes(b"{")?;
		self.increase_indentation();
		
		Ok(SimpleMapSerializer::new(self))
	}
	
	#[inline(always)]
	fn serialize_struct(self, name: &'static str, _len: usize) -> Result<Self::SerializeStruct, Self::Error>
	{
		self.serialize_bytes(name.as_bytes())?;
		
		self.write_identation()?;
		self.serialize_bytes(b"{")?;
		self.increase_indentation();
		Ok(SimpleStructSerializer::new(self))
	}
	
	#[inline(always)]
	fn serialize_struct_variant(self, _name: &'static str, _variant_index: u32, variant: &'static str, _len: usize) -> Result<Self::SerializeStructVariant, Self::Error>
	{
		self.serialize_bytes(variant.as_bytes())?;
		
		self.write_identation()?;
		self.serialize_bytes(b"{")?;
		self.increase_indentation();
		Ok(SimpleStructSerializer::new(self))
	}
}

impl<W: Write> SimpleSerializer<W>
{
	#[inline(always)]
	fn write_integer(&mut self, integer: impl Integer) -> Result<(), SimpleSerializerError>
	{
		let _ = itoa::write(&mut self.output, integer)?;
		Ok(())
	}
	
	#[inline(always)]
	fn write_float(&mut self, float: impl Floating) -> Result<(), SimpleSerializerError>
	{
		let _ = dtoa::write(&mut self.output, float)?;
		Ok(())
	}
	
	#[inline(always)]
	fn write_byte_as_hexadecimal(&mut self, byte: u8) -> Result<(), SimpleSerializerError>
	{
		self.write_u4_as_hexadecimal(byte >> 4)?;
		self.write_u4_as_hexadecimal(byte & 0b111)
	}
	
	#[inline(always)]
	fn write_u4_as_hexadecimal(&mut self, u4: u4) -> Result<(), SimpleSerializerError>
	{
		const Ascii0Digit: u8 = 48;
		const AsciiALetter: u8 = 65;
		
		let byte_to_write = match u4
		{
			0x0 ..= 0x9 => u4 + Ascii0Digit,
			
			0xA ..= 0xF => u4 + AsciiALetter,
			
			_ => unreachable!(),
		};
		let buffer = [byte_to_write];
		self.serialize_bytes(&buffer)
	}
	
	#[inline(always)]
	fn write_identation(&mut self) -> Result<(), SimpleSerializerError>
	{
		let indentation = &self.indentation[..];
		self.output.write_all(indentation)?;
		Ok(())
	}
	
	const IndentationByte: u8 = b'\t';
	
	#[inline(always)]
	fn increase_indentation(&mut self)
	{
		self.indentation.push(Self::IndentationByte);
	}
	
	#[inline(always)]
	fn decrease_indentation(&mut self)
	{
		let value = self.indentation.pop().unwrap();
		debug_assert_eq!(value, Self::IndentationByte)
	}
	
	#[inline(always)]
	fn serialize_borrow_checker_hack<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SimpleSerializerError>
	{
		let hack = unsafe { &mut * (self as *mut Self) };
		value.serialize(hack)
	}
}
