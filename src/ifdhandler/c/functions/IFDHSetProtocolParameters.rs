// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// This function should set the Protocol Type Selection (PTS) of a
	/// particular card/slot using the three PTS parameters sent
	///
	/// @ingroup IFDHandler
	/// @param[in] Lun Logical Unit Number
	/// @param[in] Protocol Desired protocol
	/// - \\ref SCARD_PROTOCOL_T0
	/// T=0 protocol
	/// - \\ref SCARD_PROTOCOL_T1
	/// T=1 protocol
	/// @param[in] Flags Logical OR of possible values to determine which PTS values
	/// to negotiate
	/// - \\ref IFD_NEGOTIATE_PTS1
	/// - \\ref IFD_NEGOTIATE_PTS2
	/// - \\ref IFD_NEGOTIATE_PTS3
	/// @param[in] PTS1 1st PTS Value
	/// @param[in] PTS2 2nd PTS Value
	/// @param[in] PTS3 3rd PTS Value\\n
	/// See ISO 7816/EMV documentation.
	///
	/// @return Error codes
	/// @retval IFD_SUCCESS Successful (\\ref IFD_SUCCESS)
	/// @retval IFD_ERROR_PTS_FAILURE Could not set PTS value (\\ref IFD_ERROR_PTS_FAILURE)
	/// @retval IFD_COMMUNICATION_ERROR Error has occurred (\\ref IFD_COMMUNICATION_ERROR)
	/// @retval IFD_PROTOCOL_NOT_SUPPORTED Protocol is not supported (\\ref IFD_PROTOCOL_NOT_SUPPORTED)
	/// @retval IFD_NOT_SUPPORTED Action not supported (\\ref IFD_NOT_SUPPORTED)
	/// @retval IFD_NO_SUCH_DEVICE The reader is no more present (\\ref IFD_NO_SUCH_DEVICE)
	pub(in crate::ifdhandler) fn IFDHSetProtocolParameters(Lun: DWORD, Protocol: DWORD, Flags: u8, PTS1: u8, PTS2: u8, PTS3: u8) -> RESPONSECODE;
}
