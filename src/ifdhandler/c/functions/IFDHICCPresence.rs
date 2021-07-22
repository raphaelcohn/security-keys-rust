// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// ***Only one thread at a time can call this for a particular `Lun`.***.
	///
	/// This function returns the status of the card inserted in the reader or slot specified by `Lun`.
	///
	/// In cases where the device supports asynchronous card insertion or removal detection, it is advised that the driver manages this through a thread so the driver does not have to send and receive a command each time this function is called.
	///
	/// * `Lun`: Logical Unit Number.
	///
	///
	/// @ingroup IFDHandler
	/// @param[in] Lun Logical Unit Number
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	/// * `IFD_ICC_NOT_PRESENT`: ICC is not present.
	pub(in crate::ifdhandler) fn IFDHICCPresence(Lun: DWORD) -> RESPONSECODE;
}
