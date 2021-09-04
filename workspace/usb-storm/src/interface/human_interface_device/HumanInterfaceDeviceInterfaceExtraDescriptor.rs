// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Human Interface Device (HID) descriptor.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanInterfaceDeviceInterfaceExtraDescriptor
{
	variant: HumanInterfaceDeviceVariant,
	
	version: Version,
	
	country_code: Option<HumanInterfaceDeviceCountryCode>,
	
	report: CollectionCommon,
	
	optional_descriptors: Vec<HumanInterfaceDeviceOptionalDescriptor>,
}

impl HumanInterfaceDeviceInterfaceExtraDescriptor
{
	/// Variant of Human Interface Device sub-class and protocol.
	#[inline(always)]
	pub const fn variant(&self) -> HumanInterfaceDeviceVariant
	{
		self.variant
	}
	
	/// Revision of the USB Human Interface Device (HID) specification.
	#[inline(always)]
	pub const fn version(&self) -> Version
	{
		self.version
	}
	
	/// Sort of a proxy for keyboard layout.
	///
	/// Effectively unused as underspecified and clearly wrong (eg Yugoslavia, no way to specify multiple English keyboard layouts, etc).
	#[inline(always)]
	pub const fn country_code(&self) -> Option<HumanInterfaceDeviceCountryCode>
	{
		self.country_code
	}
	
	/// The root of the report.
	#[inline(always)]
	pub fn report(&self) -> &CollectionCommon
	{
		&self.report
	}
	
	/// Optional descriptors in this struct.
	///
	/// Rarely present; if present, likely to be Physical descriptors.
	#[inline(always)]
	pub fn other_descriptors(&self) -> &[HumanInterfaceDeviceOptionalDescriptor]
	{
		&self.optional_descriptors
	}
}
