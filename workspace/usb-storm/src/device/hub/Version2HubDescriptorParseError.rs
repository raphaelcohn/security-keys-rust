// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version2HubDescriptorParseError
{
	#[allow(missing_docs)]
	GetDescriptor(GetStandardUsbDescriptorError),
	
	#[allow(missing_docs)]
	HubDescriptorTooShort,
	
	#[allow(missing_docs)]
	TooFewVariableBytes
	{
		number_of_downstream_ports: usize,
		
		length: usize,
		
		number_of_bytes_required_for_number_of_downstream_ports: usize,
	},
	
	/// Whilst USB permits 255 children, we cap it to 254 to use NonZeroU8 for a port number.
	///
	/// Linux caps this value as 31 (`USB_MAXCHILDREN`).
	MoreThan254Ports,
	
	#[allow(missing_docs)]
	CouldNotAllocatePortsSettings(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
}

impl Display for Version2HubDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for Version2HubDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use Version2HubDescriptorParseError::*;
		
		match self
		{
			GetDescriptor(cause) => Some(cause),
			
			CouldNotAllocatePortsSettings(cause) => Some(cause),
			
			_ => None,
		}
	}
}
