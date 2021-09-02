// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioStreamingIsochronousEndPointParseError
{
	#[allow(missing_docs)]
	BLengthIsLessThanMinimum,
	
	#[allow(missing_docs)]
	BLengthExceedsRemainingBytes,
	
	#[allow(missing_docs)]
	BLengthTooShortToHaveDescriptorSubType,
	
	#[allow(missing_docs)]
	UnrecognizedDescriptorSubType
	{
		bDescriptorSubType: DescriptorSubType,
	},
	
	#[allow(missing_docs)]
	Version1Parse(Version1AudioStreamingIsochronousEndPointParseError),
	
	#[allow(missing_docs)]
	Version2Parse(Version2AudioStreamingIsochronousEndPointParseError),
	
	#[allow(missing_docs)]
	Version3Parse(Version3AudioStreamingIsochronousEndPointParseError),
	
	#[allow(missing_docs)]
	CouldNotAllocateMemoryForUndefined(TryReserveError),
}

impl Display for AudioStreamingIsochronousEndPointParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for AudioStreamingIsochronousEndPointParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use AudioStreamingIsochronousEndPointParseError::*;
		
		match self
		{
			Version1Parse(cause) => Some(cause),
			
			Version2Parse(cause) => Some(cause),
			
			Version3Parse(cause) => Some(cause),
			
			CouldNotAllocateMemoryForUndefined(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<Version1AudioStreamingIsochronousEndPointParseError> for AudioStreamingIsochronousEndPointParseError
{
	#[inline(always)]
	fn from(cause: Version1AudioStreamingIsochronousEndPointParseError) -> Self
	{
		AudioStreamingIsochronousEndPointParseError::Version1Parse(cause)
	}
}

impl From<Version2AudioStreamingIsochronousEndPointParseError> for AudioStreamingIsochronousEndPointParseError
{
	#[inline(always)]
	fn from(cause: Version2AudioStreamingIsochronousEndPointParseError) -> Self
	{
		AudioStreamingIsochronousEndPointParseError::Version2Parse(cause)
	}
}

impl From<Version3AudioStreamingIsochronousEndPointParseError> for AudioStreamingIsochronousEndPointParseError
{
	#[inline(always)]
	fn from(cause: Version3AudioStreamingIsochronousEndPointParseError) -> Self
	{
		AudioStreamingIsochronousEndPointParseError::Version3Parse(cause)
	}
}
