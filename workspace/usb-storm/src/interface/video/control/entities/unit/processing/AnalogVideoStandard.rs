// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A processing control.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u8)]
pub enum AnalogVideoStandard
{
	#[allow(missing_docs)]
	Absent = 1 << 0,
	
	#[allow(missing_docs)]
	NTSC525Lines60Hertz = 1 << 1,
	
	#[allow(missing_docs)]
	PAL625Lines60Hertz = 1 << 2,
	
	#[allow(missing_docs)]
	SECAM625Lines60Hertz = 1 << 3,
	
	#[allow(missing_docs)]
	NTSC625Lines60Hertz = 1 << 4,
	
	#[allow(missing_docs)]
	PAL525Lines60Hertz = 1 << 5,
}
