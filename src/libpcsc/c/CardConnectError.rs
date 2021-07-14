// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// None of these errors can occur if the reader states are empty or consist entirely of ignored values.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum CardConnectError
{
	PreferredProtocolsUnsupported,
	
	CardIsUnpowered,
	
	/// Also known as unresponsive.
	CardIsMute,
	
	NoSmartCard,
	
	/// Seems to only occur during reconnect, probably due to a card being ejected.
	CardRemoved,
	
	/// Only occurs if it is impossible to obtain shared access.
	GivingUpAsCanNotGetSharedAccess,
	
	UnavailableCardReader,
	
	Communication(CommunicationError)
}

impl Display for CardConnectError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for CardConnectError
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		use self::CardConnectError::*;
		
		match self
		{
			Communication(cause) => Some(cause),
			
			_ => None,
		}
	}
}
