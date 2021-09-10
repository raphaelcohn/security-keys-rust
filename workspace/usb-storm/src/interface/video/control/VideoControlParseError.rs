// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum VideoControlParseError
{
	#[allow(missing_docs)]
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	BLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	TotalLengthLessThanHeaderDescriptor,
	
	#[allow(missing_docs)]
	TotalLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	VersionParse(VersionParseError),
	
	#[allow(missing_docs)]
	MismatchBetweenVideoProtocolAndSpecificationVersion
	{
		video_protocol: VideoProtocol,
		
		specification_version: Version
	},
	
	#[allow(missing_docs)]
	InterfaceCollectionParse(HeaderInterfacesCollectionParseError),
	
	#[allow(missing_docs)]
	EntitiesParse(EntityDescriptorParseError),
}

impl Display for VideoControlParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for VideoControlParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use VideoControlParseError::*;
		
		match self
		{
			VersionParse(cause) => Some(cause),
			
			InterfaceCollectionParse(cause) => Some(cause),
			
			EntitiesParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<HeaderInterfacesCollectionParseError> for VideoControlParseError
{
	#[inline(always)]
	fn from(cause: HeaderInterfacesCollectionParseError) -> Self
	{
		VideoControlParseError::InterfaceCollectionParse(cause)
	}
}

impl From<EntityDescriptorParseError> for VideoControlParseError
{
	#[inline(always)]
	fn from(cause: EntityDescriptorParseError) -> Self
	{
		VideoControlParseError::EntitiesParse(cause)
	}
}
