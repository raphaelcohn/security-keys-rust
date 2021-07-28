// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Mechanical features.
///
/// Rarely supported.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u32)]
pub enum MechanicalFeature
{
	#[allow(missing_docs)]
	CardAcceptMechansim = 0x00000001,
	
	#[allow(missing_docs)]
	CardEjectionMechansim = 0x00000002,
	
	#[allow(missing_docs)]
	CardCaptureMechansim = 0x00000004,
	
	#[allow(missing_docs)]
	CardLockOrUnlockMechansim = 0x00000008,
}
