// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Logitech codec extended extension controls.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u64)]
pub enum LogitechCodecExtendedExtensionControl
{
	/// `CXXU_STATIC_CONTROL`.
	Static = 1 << 0,

	/// `CXXU_DYNAMIC_CONTROL`.
	Dynamic = 1 << 1,
	
	/// `CXXU_ROI_CONTROL`.
	ROI = 1 << 2,
}
