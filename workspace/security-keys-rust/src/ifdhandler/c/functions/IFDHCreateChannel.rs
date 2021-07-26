// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// ***Only one thread at a time can call this for a particular `Lun`.***.
	///
	/// This function is required to open a communications channel to the port listed by `Channel`.
	/// For example, the first serial reader on `COM1` would link to `/dev/pcsc/1` which would be a symbolic link to`/dev/ttyS0` on some machines.
	/// This is used to help with inter-machine independence.
	///
	/// On machines with no `/dev` directory the driver writer may choose to map their Channel to whatever they feel is appropriate.
	///
	/// Once the channel is opened the reader must be in a state in which it is possible to query `IFDHICCPresence()` for card status.
	///
	/// USB readers can ignore the `Channel` parameter and query the USB bus for the particular reader by manufacturer (?vendor) identifier and product identifier.
	///
	/// * `Lun`:  Logical Unit Number, also called `slot`.
	/// * `Channel`: Channel Identifier\*
	///
	/// \* Historically, this was used as follows:-
	///
	/// * `0x000001`: `/dev/pcsc/1`.
	/// * `0x000002`: `/dev/pcsc/2`.
	/// * `0x000003`: `/dev/pcsc/3`.
	/// * `0x000004`: `/dev/pcsc/4`.
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	#[deprecated(note = "Use IFDHCreateChannelByName() function instead")]
	pub(in crate::ifdhandler) fn IFDHCreateChannel(Lun: DWORD, Channel: DWORD) -> RESPONSECODE;
}
