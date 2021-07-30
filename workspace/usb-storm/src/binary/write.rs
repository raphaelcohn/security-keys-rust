// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(super) fn write(matches: &CommandLineParser, writer: impl Write + 'static) -> Result<(), ()>
{
	let format = matches.format();
	if format.eq_ignore_ascii_case(CommandLineParser::FormatArgumentValueSimple)
	{
		serialize(writer, SimpleSerializer::new)
	}
	else if format.eq_ignore_ascii_case(CommandLineParser::FormatArgumentValueYaml)
	{
		serialize(writer, YamlSerializer::new)
	}
	else if format.eq_ignore_ascii_case(CommandLineParser::FormatArgumentValueRon)
	{
		serialize(writer, new_ron_serializer)
	}
	else if format.eq_ignore_ascii_case(CommandLineParser::FormatArgumentValueLispSExpression)
	{
		usb_devices_serialize(writer, |writer, usb_devices| lisp_s_expression_writer(writer, usb_devices))
	}
	else
	{
		unreachable!()
	}
}
