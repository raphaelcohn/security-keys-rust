// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Control rransfer recipient; value of the recipient bits in the `bmRequestType` field.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum ControlTransferRecipient
{
	#[allow(missing_docs)]
	Device = LIBUSB_RECIPIENT_DEVICE,
	
	#[allow(missing_docs)]
	Interface = LIBUSB_RECIPIENT_INTERFACE,
	
	#[allow(missing_docs)]
	EndPoint = LIBUSB_RECIPIENT_ENDPOINT,
	
	#[allow(missing_docs)]
	Other = LIBUSB_RECIPIENT_OTHER,
}
