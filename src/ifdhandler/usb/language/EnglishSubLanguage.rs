// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum EnglishSubLanguage
{
	#[allow(missing_docs)]
	UnitedStates,
	
	#[allow(missing_docs)]
	UnitedKingdom,
	
	#[allow(missing_docs)]
	Australia,
	
	#[allow(missing_docs)]
	Canada,
	
	#[allow(missing_docs)]
	NewZealand,
	
	#[allow(missing_docs)]
	Ireland,
	
	#[allow(missing_docs)]
	SouthAfrica,
	
	#[allow(missing_docs)]
	Jamaica,
	
	#[allow(missing_docs)]
	Caribbean,
	
	#[allow(missing_docs)]
	Belize,
	
	#[allow(missing_docs)]
	Trinidad,
	
	#[allow(missing_docs)]
	Zimbabwe,
	
	#[allow(missing_docs)]
	Philippines,
	
	#[allow(missing_docs)]
	Unknown(u6),
}
