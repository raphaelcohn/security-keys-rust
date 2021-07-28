// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(super) fn new_ron_serializer<W: Write>(writer: W) -> RonSerializer<W>
{
	const IncludeStructNames: bool = false;
	let config = Some(PrettyConfig::new().with_decimal_floats(true).with_extensions(Extensions::all()));
	RonSerializer::new(writer, config, IncludeStructNames).expect("Could not construct RON serializer")
}
