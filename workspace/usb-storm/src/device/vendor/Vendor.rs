// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A vendor.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Vendor
{
	identifier: VendorIdentifier,
	
	manufacturer_name: Option<LocalizedStrings>,
	
	registration: Option<VendorRegistration>,
}

impl Vendor
{
	/// Identifier.
	#[inline(always)]
	pub const fn identifier(&self) -> VendorIdentifier
	{
		self.identifier
	}
	
	/// Manufacturer Name(s).
	#[inline(always)]
	pub fn manufacturer_name(&self) -> Option<&LocalizedStrings>
	{
		self.manufacturer_name.as_ref()
	}
	
	/// Registration with the USB Implementors Forum (USB-IF), if recognized.
	#[inline(always)]
	pub const fn registration(&self) -> Option<VendorRegistration>
	{
		self.registration
	}
	
	#[inline(always)]
	pub(super) fn parse(identifier: VendorIdentifier, manufacturer_name: Option<LocalizedStrings>) -> Self
	{
		Self
		{
			identifier,
		
			manufacturer_name,
		
			registration: VendorRegistration::parse(identifier),
		}
	}
}
