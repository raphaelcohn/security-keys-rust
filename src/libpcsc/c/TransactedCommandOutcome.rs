// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum TransactedCommandOutcome<T>
{
	/// The transacted command succeeded.
	Succeeded(T),

	/// A sharing violation occurred (other than during transaction initiation, how is not clear from pcsclite's documentation).
	///
	/// The safest approach seems to be to disconnect the card after this outcome.
	SharingViolation(ConnectedCard),

	/// The transaction was interrupted by a requirement to reconnect, which has been done and has succeeded.
	///
	/// * On pcsclite on Linux and possibly on Mac OS, the transaction apparently can be continued.
	/// * On Windows, the transaction has been rolled back and must be restarted.
	///
	/// The safest approach seems to be to disconnect the card after this outcome.
	TransactionInterrupted(ConnectedCard),
}
