// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum VideoControlInterfaceExtraDescriptorParseError
{
	#[allow(missing_docs)]
	BLengthTooShortForASubTypedDescriptor,
	
	#[allow(missing_docs)]
	InputTerminalNotExpected,
	
	#[allow(missing_docs)]
	OutputTerminalNotExpected,
	
	#[allow(missing_docs)]
	SelectorUnitNotExpected,
	
	#[allow(missing_docs)]
	ProcessingUnitNotExpected,
	
	#[allow(missing_docs)]
	ExtensionUnitNotExpected,
	
	#[allow(missing_docs)]
	UnrecognizedDescriptorSubType
	{
		bDescriptorSubType: DescriptorSubType
	},
	
	#[allow(missing_docs)]
	UndefinedParse(UndefinedVideoControlInterfaceExtraDescriptorParseError),
	
	#[allow(missing_docs)]
	VideoControlParse(VideoControlParseError),
}

impl Display for VideoControlInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for VideoControlInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use VideoControlInterfaceExtraDescriptorParseError::*;
		
		match self
		{
			UndefinedParse(cause) => Some(cause),
			
			VideoControlParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<UndefinedVideoControlInterfaceExtraDescriptorParseError> for VideoControlInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: UndefinedVideoControlInterfaceExtraDescriptorParseError) -> Self
	{
		VideoControlInterfaceExtraDescriptorParseError::UndefinedParse(cause)
	}
}

impl From<VideoControlParseError> for VideoControlInterfaceExtraDescriptorParseError
{
	#[inline(always)]
	fn from(cause: VideoControlParseError) -> Self
	{
		VideoControlInterfaceExtraDescriptorParseError::VideoControlParse(cause)
	}
}
