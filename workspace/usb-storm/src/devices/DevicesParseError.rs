// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Device descriptor parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum DevicesParseError
{
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForDevices(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryToPushDeadDevice(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryToPushDeviceReferenceParseError(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
}

impl Display for DevicesParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for DevicesParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use DevicesParseError::*;
		
		match self
		{
			CouldNotAllocateMemoryForDevices(cause) => Some(cause),
			
			CouldNotAllocateMemoryToPushDeadDevice(cause) => Some(cause),
			
			CouldNotAllocateMemoryToPushDeviceReferenceParseError(cause) => Some(cause),
		}
	}
}
