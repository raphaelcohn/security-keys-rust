// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[allow(missing_docs)]
pub enum PresenceUnexpectedError
{
	ResponseTimeout,
	
	NotSupported1,
	
	ErrorTag,
	
	SetFailure,
	
	ValueReadOnly,
	
	ProtocolTypeSelectionFailure,
	
	NotSupported2,
	
	ProtocolNotSupported,
	
	PowerAction,
	
	Swallow,
	
	Eject,
	
	Confiscate,
	
	InsufficientBuffer,
	
	Undocumented(u64),
}

impl Display for PresenceUnexpectedError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for PresenceUnexpectedError
{
}

impl PresenceUnexpectedError
{
	#[inline(always)]
	pub(in crate::ifdhandler) fn parse(error: RESPONSECODE) -> Self
	{
		use PresenceUnexpectedError::*;
		
		match error
		{
			IFD_RESPONSE_TIMEOUT => ResponseTimeout,
			
			IFD_NOT_SUPPORTED => NotSupported1,
			
			IFD_ERROR_TAG => ErrorTag,
			
			IFD_ERROR_SET_FAILURE => SetFailure,
			
			IFD_ERROR_VALUE_READ_ONLY => ValueReadOnly,
			
			IFD_ERROR_PTS_FAILURE => ProtocolTypeSelectionFailure,
			
			IFD_ERROR_NOT_SUPPORTED => NotSupported2,
			
			IFD_PROTOCOL_NOT_SUPPORTED => ProtocolNotSupported,
			
			IFD_ERROR_POWER_ACTION => PowerAction,
			
			IFD_ERROR_SWALLOW => Swallow,
			
			IFD_ERROR_EJECT => Eject,
			
			IFD_ERROR_CONFISCATE => Confiscate,
			
			IFD_ERROR_INSUFFICIENT_BUFFER => InsufficientBuffer,
			
			_ => Undocumented(error as u64),
		}
	}
}
