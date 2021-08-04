// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Location.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Location
{
	logical_location: LogicalLocation,
	
	physical_location: PhysicalLocation,
}

impl Location
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn logical_location(&self) -> LogicalLocation
	{
		self.logical_location
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn physical_location(&self) -> &PhysicalLocation
	{
		&self.physical_location
	}
	
	#[inline(always)]
	fn from_libusb_device(libusb_device: NonNull<libusb_device>) -> Result<Self, DeviceParseError>
	{
		Ok
		(
			Self
			{
				logical_location: LogicalLocation::from_libusb_device(libusb_device)?,
				
				physical_location: PhysicalLocation::from_libusb_device(libusb_device),
			}
		)
	}
	
	#[inline(always)]
	fn parent_from_libusb_device(libusb_device: NonNull<libusb_device>) -> Result<Option<Self>, DeviceParseError>
	{
		match get_parent(libusb_device)
		{
			None => Ok(None),
			
			Some(parent_libusb_device) => Self::from_libusb_device(parent_libusb_device).map(Some),
		}
	}
}
