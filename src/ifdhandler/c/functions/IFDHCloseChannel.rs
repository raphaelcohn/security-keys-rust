// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// ***Only one thread at a time can call this for a particular `Lun`.***.
	///
	/// This function should close the reader communication channel for the particular reader.
	/// Prior to closing the communication channel the reader should make sure the card is powered down and the terminal is also powered down.
	///
	/// * `Lun`: Logical Unit Number (also known as 'slot').
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	pub(in crate::ifdhandler) fn IFDHCloseChannel(Lun: DWORD) -> RESPONSECODE;
}
