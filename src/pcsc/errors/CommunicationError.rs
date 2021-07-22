// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// A communication error inside PC/SC lite; nothing to do with a card or card reader.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum CommunicationError
{
	/// There is no free slot to store `hContext`.
	OutOfMemory,
	
	/// The pcsclite server is not running.
	ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished,
	
	/// An internal communications error has been detected.
	///
	/// eg the daemon supports a different version of the internal message protocol used by pcsc's client.
	InternalCommunications,
	
	/// An unspecified communication failure.
	InternalError,
}

impl Display for CommunicationError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for CommunicationError
{
}
