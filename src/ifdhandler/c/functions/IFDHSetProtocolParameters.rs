// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// This function should set the Protocol Type Selection (PTS) of a particular card/slot using the three PTS parameters sent.
	///
	/// * `Lun`: Logical Unit Number.
	/// * `Protocol`: Desired protocol, typically `SCARD_PROTOCOL_T0` or `SCARD_PROTOCOL_T1`.
	/// * `Flags`: Logical-or of possible values (`IFD_NEGOTIATE_PTS1`, `IFD_NEGOTIATE_PTS2` and `IFD_NEGOTIATE_PTS3`) to determine which Protocol Type Selection (PTS) to negotiate.
	/// * `PTS1`: First PTS Value`.
	/// * `PTS2`: Second PTS Value`.
	/// * `PTS3`: Third PTS Value`.
	///
	/// See ISO 7816 EMV specifications.
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	/// * `IFD_ERROR_PTS_FAILURE`: Could not set PTS value.
	/// * `IFD_PROTOCOL_NOT_SUPPORTED`:  Protocol is not supported.
	/// * `IFD_NOT_SUPPORTED`: Action not supported.
	pub(in crate::ifdhandler) fn IFDHSetProtocolParameters(Lun: DWORD, Protocol: DWORD, Flags: u8, PTS1: u8, PTS2: u8, PTS3: u8) -> RESPONSECODE;
}
