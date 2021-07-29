// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Control transfer request type; value of the request bits in the `bmRequestType` field.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[repr(u8)]
pub enum ControlTransferRequestType
{
	#[allow(missing_docs)]
	Standard = LIBUSB_REQUEST_TYPE_STANDARD,
	
	#[allow(missing_docs)]
	Class = LIBUSB_REQUEST_TYPE_CLASS,
	
	#[allow(missing_docs)]
	Vendor = LIBUSB_REQUEST_TYPE_VENDOR,
}
