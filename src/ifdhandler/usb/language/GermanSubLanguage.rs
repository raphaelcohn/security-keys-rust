// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum GermanSubLanguage
{
	#[allow(missing_docs)]
	Standard,
	
	#[allow(missing_docs)]
	Switzerland,
	
	#[allow(missing_docs)]
	Austria,
	
	#[allow(missing_docs)]
	Luxembourg,
	
	#[allow(missing_docs)]
	Liechtenstein,
	
	#[allow(missing_docs)]
	Unknown(u6),
}
