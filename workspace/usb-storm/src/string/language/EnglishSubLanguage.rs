// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// English dialect.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[derive(AsRefStr, Display, EnumString, EnumDefault, EnumIter)]
#[serde(deny_unknown_fields)]
#[repr(u16)]
pub enum EnglishSubLanguage
{
	#[default]
	#[allow(missing_docs)]
	UnitedStates = 0x0400,
	
	#[allow(missing_docs)]
	UnitedKingdom = 0x0800,
	
	#[allow(missing_docs)]
	Australia = 0x0C00,
	
	#[allow(missing_docs)]
	Canada = 0x1000,
	
	#[allow(missing_docs)]
	NewZealand = 0x1400,
	
	#[allow(missing_docs)]
	Ireland = 0x1800,
	
	#[allow(missing_docs)]
	SouthAfrica = 0x1C00,
	
	#[allow(missing_docs)]
	Jamaica = 0x2000,
	
	#[allow(missing_docs)]
	Caribbean = 0x2400,
	
	#[allow(missing_docs)]
	Belize = 0x2800,
	
	#[allow(missing_docs)]
	Trinidad = 0x2C00,
	
	#[allow(missing_docs)]
	Zimbabwe = 0x3000,
	
	#[allow(missing_docs)]
	Philippines = 0x3400,
}

sub_language!(EnglishSubLanguage);
