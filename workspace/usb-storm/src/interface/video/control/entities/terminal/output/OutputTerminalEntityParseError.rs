// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum OutputTerminalEntityParseError
{
	#[allow(missing_docs)]
	BLengthTooShort
	{
		bLength: u8,
	},
	
	#[allow(missing_docs)]
	InvalidDescriptionString(GetLocalizedStringError),
	
	#[allow(missing_docs)]
	InputTerminalType
	{
		input_specific_terminal_type: InputSpecificTerminalTypeDiscriminants,
	},
	
	#[allow(missing_docs)]
	CanNotAllocateMemoryForOutputVendorSpecificTerminalType(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	CanNotAllocateMemoryForOutputDisplayTerminalType(#[serde(with = "TryReserveErrorRemote")] TryReserveError),
	
	#[allow(missing_docs)]
	CanNotAllocateMemoryForUsbTerminalType
	{
		usb_format_type: UsbTerminalTypeDiscriminants,
		
		#[serde(with = "TryReserveErrorRemote")] cause: TryReserveError,
	},
	
	#[allow(missing_docs)]
	CanNotAllocateMemoryForExternalTerminalType
	{
		external_format_type: ExternalTerminalTypeDiscriminants,
		
		#[serde(with = "TryReserveErrorRemote")] cause: TryReserveError,
	},
	
	#[allow(missing_docs)]
	CanNotAllocateMemoryForUnknownTerminalType
	{
		wTerminalType: u16,
		
		#[serde(with = "TryReserveErrorRemote")] cause: TryReserveError,
	},
	
	#[allow(missing_docs)]
	MediaTransportParse(MediaTransportParseError),
}

impl Display for OutputTerminalEntityParseError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for OutputTerminalEntityParseError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use OutputTerminalEntityParseError::*;
		
		match self
		{
			InvalidDescriptionString(cause) => Some(cause),
			
			CanNotAllocateMemoryForOutputVendorSpecificTerminalType(cause) => Some(cause),
			
			CanNotAllocateMemoryForOutputDisplayTerminalType(cause) => Some(cause),
			
			CanNotAllocateMemoryForUsbTerminalType { cause, .. } => Some(cause),
			
			CanNotAllocateMemoryForExternalTerminalType { cause, .. } => Some(cause),
			
			CanNotAllocateMemoryForUnknownTerminalType { cause, .. } => Some(cause),
			
			MediaTransportParse(cause) => Some(cause),
			
			_ => None,
		}
	}
}

impl From<MediaTransportParseError> for OutputTerminalEntityParseError
{
	#[inline(always)]
	fn from(cause: MediaTransportParseError) -> Self
	{
		OutputTerminalEntityParseError::MediaTransportParse(cause)
	}
}
