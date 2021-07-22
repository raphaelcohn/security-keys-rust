// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// Why was a card or card reader unavailable?
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum UnavailableError
{
	/// Seems to only occur during connect and reconnect.
	CardIsUnpowered,
	
	/// Seems to only occur during connect and reconnect.
	///
	/// Also known as unresponsive.
	CardIsMute,
	
	/// Seems to only occur during reconnect, probably due to a card being ejected.
	CardRemoved,
	
	#[allow(missing_docs)]
	NoCard,
	
	#[allow(missing_docs)]
	CardReaderUnavailable,
}

impl Display for UnavailableError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for UnavailableError
{
}
