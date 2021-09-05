// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


trait GoodAndBadDevicesExt
{
	fn which_serialize(&self, format: &str, writer: impl Write + 'static) -> Result<(), SerializingError>;
	
	fn serialize_self<'a, W: Write, F: FnOnce(W) -> S, S, E>(&self, writer: W, constructor: F) -> Result<(), E>
	where &'a mut S: 'static + Serializer<Ok=(), Error=E>;
}

impl GoodAndBadDevicesExt for GoodAndBadDevices
{
	#[inline(always)]
	fn which_serialize(&self, format: &str, writer: impl Write + 'static) -> Result<(), SerializingError>
	{
		if format.eq_ignore_ascii_case(CommandLineParser::FormatArgumentValueJson)
		{
			self.serialize_self(writer, JsonSerializer::new)?
		}
		else if format.eq_ignore_ascii_case(CommandLineParser::FormatArgumentValueJsonPretty)
		{
			self.serialize_self(writer, JsonSerializer::pretty)?
		}
		else if format.eq_ignore_ascii_case(CommandLineParser::FormatArgumentValueLispSExpression)
		{
			lisp_s_expression_writer(writer, self)?
		}
		else if format.eq_ignore_ascii_case(CommandLineParser::FormatArgumentValueRon)
		{
			self.serialize_self(writer, new_ron_serializer)?
		}
		else if format.eq_ignore_ascii_case(CommandLineParser::FormatArgumentValueSimple)
		{
			self.serialize_self(writer, SimpleSerializer::new)?
		}
		else if format.eq_ignore_ascii_case(CommandLineParser::FormatArgumentValueYaml)
		{
			self.serialize_self(writer, YamlSerializer::new)?
		}
		else
		{
			unreachable!()
		}
		Ok(())
	}
	
	#[inline(always)]
	fn serialize_self<'a, W: Write, F: FnOnce(W) -> S, S, E>(&self, writer: W, constructor: F) -> Result<(), E>
	where &'a mut S: 'static + Serializer<Ok=(), Error=E>
	{
		let mut serializer = constructor(writer);
		let reference = &mut serializer;
		let borrow_checker_hack = unsafe { &mut * (reference as *mut S) };
		self.serialize(borrow_checker_hack)?;
		Ok(())
	}
}
