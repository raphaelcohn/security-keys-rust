// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u16)]
pub(crate) enum SpanishSubLanguage
{
	#[allow(missing_docs)]
	Traditional = 0x0400,
	
	#[allow(missing_docs)]
	Mexico = 0x0800,
	
	#[allow(missing_docs)]
	Modern = 0x0C00,
	
	#[allow(missing_docs)]
	Guatemala = 0x1000,
	
	#[allow(missing_docs)]
	CostaRica = 0x1400,
	
	#[allow(missing_docs)]
	Panama = 0x1800,
	
	#[allow(missing_docs)]
	DominicanRepublic = 0x1C00,
	
	#[allow(missing_docs)]
	Venezuela = 0x2000,
	
	#[allow(missing_docs)]
	Colombia = 0x2400,
	
	#[allow(missing_docs)]
	Peru = 0x2800,
	
	#[allow(missing_docs)]
	Argentina = 0x2C00,
	
	#[allow(missing_docs)]
	Ecuador = 0x3000,
	
	#[allow(missing_docs)]
	Chile = 0x3400,
	
	#[allow(missing_docs)]
	Uruguay = 0x3800,
	
	#[allow(missing_docs)]
	Paraguay = 0x3C00,
	
	#[allow(missing_docs)]
	Bolivia = 0x4000,
	
	#[allow(missing_docs)]
	ElSalvador = 0x4400,
	
	#[allow(missing_docs)]
	Honduras = 0x4800,
	
	#[allow(missing_docs)]
	Nicaragua = 0x4C00,
	
	#[allow(missing_docs)]
	PuertoRico = 0x5000,
	
	#[allow(missing_docs)]
	Unknown(u6),
}
