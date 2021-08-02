// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Human Interface Device (HID) interface sub class.
///
/// See Device Class Definition for Human Interface Devices (HID) Version 1.11, Section 4.2 Subclass.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum HumanInterfaceDeviceInterfaceSubClass
{
	/// Not a boot device.
	None
	{
		/// Should be `None` if known.
		unknown_protocol: Option<NonZeroU8>,
	},
	
	/// A boot device.
	Boot(HumanInterfaceDeviceInterfaceBootProtocol),

	Unrecognized(UnrecognizedSubClass),
}
