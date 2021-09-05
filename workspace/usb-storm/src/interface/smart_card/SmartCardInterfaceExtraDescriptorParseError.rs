// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Smart Card descriptor parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum SmartCardInterfaceExtraDescriptorParseError
{
	#[allow(missing_docs)]
	DescriptorIsNeitherOfficialOrVendorSpecific
	{
		actual: DescriptorType,
	
		expected: DescriptorType,
	},
	
	#[allow(missing_docs)]
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	BLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	Version(VersionParseError),
	
	/// Features are invalid.
	Features(FeaturesParseError),
	
	#[allow(missing_docs)]
	UnsupportedClassGetResponse(u8),
	
	#[allow(missing_docs)]
	UnsupportedClassEnvelope(u8),
}

impl Display for SmartCardInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for SmartCardInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use SmartCardInterfaceExtraDescriptorParseError::*;
		
		match self
		{
			Version(cause) => Some(cause),
			
			Features(cause) => Some(cause),
			
			_ => None,
		}
	}
}
