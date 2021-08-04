// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// German dialect.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[derive(AsRefStr, Display, EnumString, EnumDefault)]
#[serde(deny_unknown_fields)]
#[repr(u16)]
pub enum GermanSubLanguage
{
	#[default]
	#[allow(missing_docs)]
	Standard = 0x0400,
	
	#[allow(missing_docs)]
	Switzerland = 0x0800,
	
	#[allow(missing_docs)]
	Austria = 0x0C00,
	
	#[allow(missing_docs)]
	Luxembourg = 0x1000,
	
	#[allow(missing_docs)]
	Liechtenstein = 0x1400,
}

sub_language!(GermanSubLanguage);
