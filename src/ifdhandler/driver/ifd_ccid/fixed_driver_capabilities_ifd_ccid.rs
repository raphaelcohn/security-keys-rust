// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[inline(always)]
pub(super) const fn fixed_driver_capabilities_ifd_ccid() -> FixedDriverCapabilities
{
	const CCID_DRIVER_MAX_READERS: usize = 16;
	
	FixedDriverCapabilities
	{
		TAG_IFD_SIMULTANEOUS_ACCESS: new_non_zero_usize(CCID_DRIVER_MAX_READERS),
		
		#[cfg(any(target_os = "ios", target_os = "macos"))] TAG_IFD_THREAD_SAFE: false,
		#[cfg(not(any(target_os = "ios", target_os = "macos")))] TAG_IFD_THREAD_SAFE: true,
		
		TAG_IFD_SLOT_THREAD_SAFE: false,
		
		usb_device_information_database: UsbDeviceInformationDatabase::from_hash_map(hashmap!
		[
			(0x08E6, 0x5503) => composite(0x00, 2),
			(0x08E6, 0x5504) => composite(0x00, 2),
			(0x076B, 0x5422) => composite(0x00, 2),
			(0x096E, 0x060D) => composite(0x00, 4),
		]),
	}
}
