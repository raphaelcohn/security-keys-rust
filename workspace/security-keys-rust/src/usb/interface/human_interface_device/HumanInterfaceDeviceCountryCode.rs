// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Sort of a proxy for keyboard layout.
///
/// Effectively unused as underspecified and clearly wrong (eg Yugoslavia, no way to specify multiple English keyboard layouts, etc).
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
// `#[repr(NonZeroU8)].
#[repr(u8)]
pub enum HumanInterfaceDeviceCountryCode
{
	Arabic = 1,
	
	Belgian = 2,

	CanadianBilingual = 3,
	CanadianFrench = 4,
	
	CzechRepublic = 5,
	Slovakia = 24,
	
	Danish = 6,
	
	Finnish = 7,
	
	French = 8,
	
	German = 9,
	
	Greek = 10,
	
	Hebrew = 11,
	
	Hungary = 12,
	
	/// ISO.
	International = 13,
	
	NetherlandsDutch = 18,
	
	Norwegian = 19,
	
	/// Farsi
	Persian = 20,
	
	Poland = 21,
	
	Portuguese = 22,
	
	Russia = 23,
	
	Spanish = 25,
	LatinAmerica = 17,
	
	Swedish = 26,
	
	SwissFrench = 27,
	SwissGerman = 28,
	Switzerland = 29,
	
	Taiwan = 30,
	
	UK = 32,
	
	US = 33,
	
	Yugoslavia = 34,
	
	TurkishQ = 31,
	TurkishF = 35,
	/*
	
	
01
02
03
04
05
06
07
08
09
10
11
12
13
14
15
16

Not Supported Arabic
Belgian Canadian-Biling
Canadian-Frenc
Czech Republic Danish
Finnish
French
German
Greek
Hebrew
Hungary International (IS
Italian
Japan (Katakana
Korean

	 */
}
