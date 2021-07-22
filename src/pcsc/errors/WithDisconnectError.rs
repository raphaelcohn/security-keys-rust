// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// An erro occurred that forced a disconnect of the card, which may also have errored.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct WithDisconnectError<E: error::Error>
{
	/// The error that originally occurred.
	cause: E,
	
	/// If `Some()`, an error that occurred during disconnect of the card.
	disconnect_error: Option<UnavailableOrCommunicationError>,
}

impl<E: error::Error> Display for WithDisconnectError<E>
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter) -> fmt::Result
	{
		Debug::fmt(self, f)
	}
}

impl<E: 'static + error::Error> error::Error for WithDisconnectError<E>
{
	#[inline(always)]
	fn source(&self) -> Option<&(dyn error::Error + 'static)>
	{
		Some(&self.cause)
	}
}

impl<E: error::Error> WithDisconnectError<E>
{
	#[inline(always)]
	pub(crate) fn new(cause: E, disconnect_error: Result<(), UnavailableOrCommunicationError>) -> Self
	{
		Self
		{
			cause,
		
			disconnect_error: disconnect_error.err(),
		}
	}
}
