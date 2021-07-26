// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u16)]
pub(crate) enum ArabicSubLanguage
{
	#[allow(missing_docs)]
	SaudiArabia = 0x0400,
	
	#[allow(missing_docs)]
	Iraq = 0x0800,
	
	#[allow(missing_docs)]
	Egypt = 0x0C00,
	
	#[allow(missing_docs)]
	Libya = 0x1000,
	
	#[allow(missing_docs)]
	Algeria = 0x1400,
	
	#[allow(missing_docs)]
	Morocco = 0x1800,
	
	#[allow(missing_docs)]
	Tunisia = 0x1C00,
	
	#[allow(missing_docs)]
	Oman = 0x2000,
	
	#[allow(missing_docs)]
	Yemen = 0x2400,
	
	#[allow(missing_docs)]
	Syria = 0x2800,
	
	#[allow(missing_docs)]
	Jordan = 0x2C00,
	
	#[allow(missing_docs)]
	Lebanon = 0x3000,
	
	#[allow(missing_docs)]
	Kuwait = 0x3400,
	
	#[allow(missing_docs)]
	UnitedArabEmirates = 0x3800,
	
	#[allow(missing_docs)]
	Bahrain = 0x3C00,
	
	#[allow(missing_docs)]
	Qatar = 0x4000,
	
	#[allow(missing_docs)]
	Unknown(u6),
}
