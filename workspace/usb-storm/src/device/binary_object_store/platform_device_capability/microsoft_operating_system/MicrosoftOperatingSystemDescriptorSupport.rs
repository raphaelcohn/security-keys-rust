// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Microsoft Operating System Descriptor support.
///
/// See [Microsoft OS Descriptors for USB Devices](https://docs.microsoft.com/en-us/windows-hardware/drivers/usbcon/microsoft-defined-usb-descriptors).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum MicrosoftOperatingSystemDescriptorSupport
{
	/// Details can be retrieved using the `GET_MS_DESCRIPTOR` control request and paging to get up to 1Mb of data.
	///
	/// Supported by Microsofot up to and including Windows 8.1.
	Version_1_0
	{
		/// Vendor code to supply to the `GET_MS_DESCRIPTOR` control request.
		vendor_code: MicrosoftVendorCode,
	},

	/// Details are in the Binary Object Store.
	///
	/// Supported by Microsoft from Windows 8.1 onwards (overlaps with support for Version 1.0).
	Version_2_0,
}
