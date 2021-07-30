// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Human Interface Device (HID).
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u16)]
pub enum HumanInterfaceDeviceSubLanguage
{
	#[allow(missing_docs)]
	UsageDataDescriptor = 0x0400,
	
	#[allow(missing_docs)]
	VendorDefined1 = 0xF000,
	
	#[allow(missing_docs)]
	VendorDefined2 = 0xF400,
	
	#[allow(missing_docs)]
	VendorDefined3 = 0xF800,
	
	#[allow(missing_docs)]
	VendorDefined4 = 0xFC00,
	
	#[allow(missing_docs)]
	Unknown(u6),
}
