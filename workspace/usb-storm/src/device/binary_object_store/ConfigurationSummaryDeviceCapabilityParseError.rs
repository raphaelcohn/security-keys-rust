// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A parse error.
#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum ConfigurationSummaryDeviceCapabilityParseError
{
	TooShort,

	Version(VersionParseError),
	
	TooManyConfigurations
	{
		bConfigurationCount: u8,
	},
	
	DuplicateConfigurationIndex
	{
		configuration_descriptor_index: u8,
	}
}

impl Display for ConfigurationSummaryDeviceCapabilityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for ConfigurationSummaryDeviceCapabilityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use ConfigurationSummaryDeviceCapabilityParseError::*;
		
		match self
		{
			Version(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<VersionParseError> for ConfigurationSummaryDeviceCapabilityParseError
{
	#[inline(always)]
	fn from(cause: VersionParseError) -> Self
	{
		ConfigurationSummaryDeviceCapabilityParseError::Version(cause)
	}
}
