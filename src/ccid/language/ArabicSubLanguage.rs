// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum ArabicSubLanguage
{
	#[allow(missing_docs)]
	SaudiArabia,
	
	#[allow(missing_docs)]
	Iraq,
	
	#[allow(missing_docs)]
	Egypt,
	
	#[allow(missing_docs)]
	Libya,
	
	#[allow(missing_docs)]
	Algeria,
	
	#[allow(missing_docs)]
	Morocco,
	
	#[allow(missing_docs)]
	Tunisia,
	
	#[allow(missing_docs)]
	Oman,
	
	#[allow(missing_docs)]
	Yemen,
	
	#[allow(missing_docs)]
	Syria,
	
	#[allow(missing_docs)]
	Jordan,
	
	#[allow(missing_docs)]
	Lebanon,
	
	#[allow(missing_docs)]
	Kuwait,
	
	#[allow(missing_docs)]
	UnitedArabEmirates,
	
	#[allow(missing_docs)]
	Bahrain,
	
	#[allow(missing_docs)]
	Qatar,
	
	#[allow(missing_docs)]
	Unknown(u6),
}
