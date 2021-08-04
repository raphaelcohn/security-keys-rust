// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Device Firmware Upgrade (DFU) descriptor.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceFirmwareUpgradeInterfaceAdditionalDescriptor
{
	will_detach: bool,
	
	manifestation_tolerant: bool,
	
	can_upload: bool,
	
	can_download: bool,
	
	maximum_detach_time_out_milliseconds: u16,
	
	maximum_number_of_bytes_per_control_write_transaction: u16,
	
	version: Option<Version>,
}

impl DeviceFirmwareUpgradeInterfaceAdditionalDescriptor
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn will_detach(&self) -> bool
	{
		self.will_detach
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn manifestation_tolerant(&self) -> bool
	{
		self.manifestation_tolerant
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn can_upload(&self) -> bool
	{
		self.can_upload
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn can_download(&self) -> bool
	{
		self.can_download
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_detach_time_out_milliseconds(&self) -> u16
	{
		self.maximum_detach_time_out_milliseconds
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_number_of_bytes_per_control_write_transaction(&self) -> u16
	{
		self.maximum_number_of_bytes_per_control_write_transaction
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn version(&self) -> Option<Version>
	{
		self.version
	}
}
