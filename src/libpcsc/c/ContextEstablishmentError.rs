// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// None of these errors can occur on Linux.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum ContextEstablishmentError
{
	/// There is no free slot to store `hContext`.
	#[cfg(any(target_os = "macos", target_os = "windows"))] OutOfMemory,
	
	/// The pcsclite server is not running.
	#[cfg(any(target_os = "macos", target_os = "windows"))] ThereIsNoDaemonRunningOrConnectionWithTheDaemonCouldNotBeEstablished,
	
	/// An internal communications error has been detected.
	///
	/// eg the daemon supports a different version of the internal message protocol used by libpcsc's client.
	#[cfg(any(target_os = "macos", target_os = "windows"))] InternalCommunications,
}

impl Display for ContextEstablishmentError
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl error::Error for ContextEstablishmentError
{
}
