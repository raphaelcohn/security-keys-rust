// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(crate) struct UsbDeviceInformationDatabase<T>(HashMap<(UsbVendorIdentifier, UsbProductIdentifier), T>);

impl<T> UsbDeviceInformationDatabase<T>
{
	#[inline(always)]
	pub(crate) fn empty() -> Self
	{
		Self(HashMap::new())
	}
	
	#[inline(always)]
	pub(crate) fn from_hash_map(hash_map: HashMap<(UsbVendorIdentifier, UsbProductIdentifier), T>) -> Self
	{
		Self(hash_map)
	}
	
	#[inline(always)]
	pub(crate) fn get(&self, vendor_identifier: UsbVendorIdentifier, product_identifier: UsbProductIdentifier) -> Option<&T>
	{
		self.0.get(&(vendor_identifier, product_identifier))
	}
}
