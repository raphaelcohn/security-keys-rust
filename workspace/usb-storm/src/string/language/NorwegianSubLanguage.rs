// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Norwegian dialect.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[derive(AsRefStr, Display, EnumString, EnumDefault, EnumIter)]
#[serde(deny_unknown_fields)]
#[repr(u16)]
pub enum NorwegianSubLanguage
{
	#[default]
	#[allow(missing_docs)]
	Bokmål = 0x0400,
	
	#[allow(missing_docs)]
	Nynorsk = 0x0800,
}

sub_language!(NorwegianSubLanguage);
