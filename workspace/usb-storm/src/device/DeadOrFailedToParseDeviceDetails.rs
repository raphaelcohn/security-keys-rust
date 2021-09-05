// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Details of a device that is dead or failed to parse.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeadOrFailedToParseDeviceDetails
{
	vendor_identifier: VendorIdentifier,
	
	product_identifier: ProductIdentifier,
	
	#[serde(flatten)]
	location: Location,
}

impl DeadOrFailedToParseDeviceDetails
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn vendor_identifier(&self) -> VendorIdentifier
	{
		self.vendor_identifier
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn product_identifier(&self) -> ProductIdentifier
	{
		self.product_identifier
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn location(&self) -> &Location
	{
		&self.location
	}
}
