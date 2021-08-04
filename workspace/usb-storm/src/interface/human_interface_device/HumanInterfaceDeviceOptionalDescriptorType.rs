// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// The only type that seems likely is a Physical descriptor, with `bDescriptorType` of 0x23.
///
/// Types other than `Physical` and `Reserved` are rejected and treated as errors.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u8)]
pub enum HumanInterfaceDeviceOptionalDescriptorType
{
	/// A physical descriptor.
	Physical,
	
	/// 0x24 to 0x2F inclusive.
	Reserved(u8),
}
