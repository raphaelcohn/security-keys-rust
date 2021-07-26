// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u16)]
pub(crate) enum ChineseSubLanguage
{
	#[allow(missing_docs)]
	Taiwan = 0x0400,
	
	#[allow(missing_docs)]
	China = 0x0800,
	
	#[allow(missing_docs)]
	HongKong = 0x0C00,
	
	#[allow(missing_docs)]
	Singapore = 0x1000,
	
	#[allow(missing_docs)]
	Macau = 0x1400,
	
	#[allow(missing_docs)]
	Unknown(u6),
}
