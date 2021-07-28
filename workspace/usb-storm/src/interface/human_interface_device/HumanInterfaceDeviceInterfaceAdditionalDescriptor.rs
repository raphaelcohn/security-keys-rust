// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Human Interface Device (HID) descriptor.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanInterfaceDeviceInterfaceAdditionalDescriptor
{
	/// Revision of the USB HID specification.
	version: UsbVersion,
	
	country_code: Option<HumanInterfaceDeviceCountryCode>,
	
	report_descriptor_length: u16,
	
	/// A maximum of 254.
	number_of_other_descriptors: u8,
	
	other_descriptors: Vec<u8>,
}
