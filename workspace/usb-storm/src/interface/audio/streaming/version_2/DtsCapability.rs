// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// DTS capability.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u8)]
pub enum DtsCapability
{
	#[allow(missing_docs)]
	Core = 1 << 0,
	
	#[allow(missing_docs)]
	Lossles = 1 << 1,
	
	#[allow(missing_docs)]
	LBR = 1 << 2,
	
	#[allow(missing_docs)]
	MultipleStreamMixing = 1 << 3,
	
	#[allow(missing_docs)]
	DualDecode = 1 << 4,
}
