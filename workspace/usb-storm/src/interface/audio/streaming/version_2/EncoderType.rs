// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Encoder type.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum EncoderType
{
	#[allow(missing_docs)]
	Undefined,
	
	#[allow(missing_docs)]
	Other,
	
	#[allow(missing_docs)]
	MPEG,
	
	#[allow(missing_docs)]
	AC_3,
	
	#[allow(missing_docs)]
	WMA,
	
	#[allow(missing_docs)]
	DTS,
	
	#[allow(missing_docs)]
	Unrecognized
	{
		encoder_type_code: u8,
	},
}
