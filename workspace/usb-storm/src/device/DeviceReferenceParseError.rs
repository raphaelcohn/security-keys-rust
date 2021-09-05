// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// High-level error caused when trying to parse a device.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum DeviceReferenceParseError
{
	#[allow(missing_docs)]
	InvalidLocation
	{
		vendor_identifier: VendorIdentifier,
		
		product_identifier: ProductIdentifier,
		
		cause: LocationError,
	},
	
	#[allow(missing_docs)]
	DeviceParse
	{
		details: DeadOrFailedToParseDeviceDetails,
		
		cause: DeviceParseError,
	},
}

impl Display for DeviceReferenceParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for DeviceReferenceParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use DeviceReferenceParseError::*;
		
		match self
		{
			InvalidLocation { cause, .. } => Some(cause),
			
			DeviceParse { cause, .. } => Some(cause),
		}
	}
}
