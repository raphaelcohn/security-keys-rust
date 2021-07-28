// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(crate) trait DeviceOrInterface
{
	/// Communications and Communications Device Class (CDC) Control.
	///
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClass02h>.
	const CommunicationsAndCommunicationsDeviceClassControlClass: u8 = 0x02;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassDCh>.
	const DiagnosticDeviceClass: u8 = 0xDC;
	
	/// See https://www.usb.org/defined-class-codes#anchor_BaseClassEFh.
	const MiscellaneousClass: u8 = 0xEF;
	
	/// See <https://www.usb.org/defined-class-codes#anchor_BaseClassFFh>.
	const VendorSpecificClass: u8 = 0xFF;
	const VendorSpecificSubClass: u8 = 0xFF;
	const VendorSpecificProtocol: u8 = 0xFF;
}
