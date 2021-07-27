// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(super) struct CommandLineParser<'a>(ArgMatches<'a>);

impl<'a> CommandLineParser<'a>
{
	const FormatArgumentName: &'static str = "format";
	
	pub(super) const FormatArgumentValueSimple: &'static str = "simple";
	
	pub(super) const FormatArgumentValueYaml: &'static str = "YAML";
	
	pub(super) const FormatArgumentValueRon: &'static str = "RON";
	
	pub(super) const FormatArgumentValueLispSExpression: &'static str = "lisp-s-expression";
	
	const FormatArgumentDefault: &'static str = Self::FormatArgumentValueYaml;
	
	pub(super) fn parse() -> Self
	{
		let app = App::new("rust-security-keys")
			.name(crate_name!())
			.version(crate_version!())
			.author(crate_authors!("\n"))
			.about("Enumerates all USB devices with as much detail as possible; very intolerant of USB specification violations")
			.arg
			(
				Arg::with_name(Self::FormatArgumentName)
					.long("format")
					.short("f")
					.value_name("FORMAT")
					.help("Changes the output format")
					.empty_values(false)
					.takes_value(true)
					.case_insensitive(true)
					.multiple(false)
					.default_value(Self::FormatArgumentDefault)
					.possible_value(Self::FormatArgumentValueSimple)
					.possible_value(Self::FormatArgumentValueYaml)
					.possible_value(Self::FormatArgumentValueRon)
					.possible_value(Self::FormatArgumentValueLispSExpression)
			);
		Self(app.get_matches())
	}
	
	pub(super) fn format(&self) -> &str
	{
		self.0.value_of(Self::FormatArgumentName).unwrap_or(Self::FormatArgumentDefault)
	}
}
