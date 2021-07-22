// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// This trait represents driver capabilities that can only be discovered using `IFDHGetCapabilities()` with a `Lun`, yet are nothing to do with either a device or a slot.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FixedDriverCapabilities
{
	TAG_IFD_SIMULTANEOUS_ACCESS: NonZeroUsize,
	
	TAG_IFD_THREAD_SAFE: bool,
	
	TAG_IFD_SLOT_THREAD_SAFE: bool,

	usb_device_information_database: UsbDeviceInformationDatabase<FixedUsbDeviceCapabilities>,
}

impl FixedDriverCapabilities
{
	#[inline(always)]
	fn unknown() -> &'static Self
	{
		static Singleton: SyncLazy<Self> = SyncLazy::new(||
		{
			Self
			{
				TAG_IFD_SIMULTANEOUS_ACCESS: new_non_zero_usize(1),
				
				TAG_IFD_THREAD_SAFE: false,
				
				TAG_IFD_SLOT_THREAD_SAFE: false,
				
				usb_device_information_database: UsbDeviceInformationDatabase::default(),
			}
		});
		
		&Singleton
	}
	
	#[inline]
	fn fixed_usb_device_capabilities(&self, vendor_identifier: UsbVendorIdentifier, product_identifier: UsbProductIdentifier) -> Option<&FixedUsbDeviceCapabilities>
	{
		self.usb_device_information_database.get(vendor_identifier, product_identifier)
	}
}
