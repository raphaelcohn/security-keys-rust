// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Vendor registration details with the USB Implementors Forum (USB-IF).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VendorRegistration
{
	registration_name: &'static str,
	
	is_obsolete: bool,
}

impl VendorRegistration
{
	/// Name registered with the USB Implementors Forum (USB-IF).
	#[inline(always)]
	pub const fn registration_name(self) -> &'static str
	{
		self.registration_name
	}
	
	/// Is this an obsolete registration?
	#[inline(always)]
	pub const fn is_obsolete(self) -> bool
	{
		self.is_obsolete
	}
	
	#[inline(always)]
	const fn new(name: &'static str, is_obsolete: bool) -> Self
	{
		Self
		{
			registration_name: name,
		
			is_obsolete,
		}
	}
}

include!(concat!(env!("OUT_DIR"), "/VendorRegistration.rs"));
