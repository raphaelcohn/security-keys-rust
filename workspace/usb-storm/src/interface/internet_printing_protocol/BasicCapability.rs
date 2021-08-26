// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Basic capability.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u8)]
pub enum BasicCapability
{
	#[allow(missing_docs)]
	Print = 1 << 0,
	
	#[allow(missing_docs)]
	Scan = 1 << 1,
	
	#[allow(missing_docs)]
	Fax = 1 << 2,
	
	#[allow(missing_docs)]
	VendorSpecific = 1 << 3,
	
	#[allow(missing_docs)]
	AnyHttp11OverUsb = 1 << 5,
}
