// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndPointExtraDescriptorParseError
{
	#[allow(missing_docs)]
	SuperSpeedEndPointCompanion(SuperSpeedEndPointCompanionDescriptorParseError),
	
	#[allow(missing_docs)]
	UsbAttachedScsiPipe(UsbAttachedScsiPipeParseError),
	
	#[allow(missing_docs)]
	AudioStreaming(AudioStreamingIsochronousEndPointParseError),
}

impl Display for EndPointExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for EndPointExtraDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use EndPointExtraDescriptorParseError::*;
		
		match self
		{
			SuperSpeedEndPointCompanion(cause) => Some(cause),
			
			UsbAttachedScsiPipe(cause) => Some(cause),
			
			AudioStreaming(cause) => Some(cause),
		}
	}
}

impl From<SuperSpeedEndPointCompanionDescriptorParseError> for EndPointExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: SuperSpeedEndPointCompanionDescriptorParseError) -> Self
	{
		EndPointExtraDescriptorParseError::SuperSpeedEndPointCompanion(cause)
	}
}

impl From<UsbAttachedScsiPipeParseError> for EndPointExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: UsbAttachedScsiPipeParseError) -> Self
	{
		EndPointExtraDescriptorParseError::UsbAttachedScsiPipe(cause)
	}
}

impl From<AudioStreamingIsochronousEndPointParseError> for EndPointExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: AudioStreamingIsochronousEndPointParseError) -> Self
	{
		EndPointExtraDescriptorParseError::AudioStreaming(cause)
	}
}
