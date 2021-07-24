// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum SpanishSubLanguage
{
	#[allow(missing_docs)]
	Traditional,
	
	#[allow(missing_docs)]
	Mexico,
	
	#[allow(missing_docs)]
	Modern,
	
	#[allow(missing_docs)]
	Guatemala,
	
	#[allow(missing_docs)]
	CostaRica,
	
	#[allow(missing_docs)]
	Panama,
	
	#[allow(missing_docs)]
	DominicanRepublic,
	
	#[allow(missing_docs)]
	Venezuela,
	
	#[allow(missing_docs)]
	Colombia,
	
	#[allow(missing_docs)]
	Peru,
	
	#[allow(missing_docs)]
	Argentina,
	
	#[allow(missing_docs)]
	Ecuador,
	
	#[allow(missing_docs)]
	Chile,
	
	#[allow(missing_docs)]
	Uruguay,
	
	#[allow(missing_docs)]
	Paraguay,
	
	#[allow(missing_docs)]
	Bolivia,
	
	#[allow(missing_docs)]
	ElSalvador,
	
	#[allow(missing_docs)]
	Honduras,
	
	#[allow(missing_docs)]
	Nicaragua,
	
	#[allow(missing_docs)]
	PuertoRico,
	
	#[allow(missing_docs)]
	Unknown(u6),
}
