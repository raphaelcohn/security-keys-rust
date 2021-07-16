// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// This function performs an APDU exchange with the card/slot specified by
	/// Lun. The driver is responsible for performing any protocol specific
	/// exchanges such as T=0, 1, etc. differences. Calling this function will
	/// abstract all protocol differences.
	///
	/// @ingroup IFDHandler
	/// @param[in] Lun Logical Unit Number
	/// @param[in] SendPci contains two structure members
	/// - Protocol 0, 1, ... 14\\n
	/// T=0 ... T=14
	/// - Length\\n
	/// Not used.
	/// @param[in] TxBuffer Transmit APDU\\n
	/// Example: \"\\x00\\xA4\\x00\\x00\\x02\\x3F\\x00\"
	/// @param[in] TxLength Length of this buffer
	/// @param[out] RxBuffer Receive APDU\\n
	/// Example: \"\\x61\\x14\"
	/// @param[in,out] RxLength Length of the received APDU\\n
	/// This function will be passed the size of the buffer of RxBuffer and
	/// this function is responsible for setting this to the length of the
	/// received APDU response. This should be ZERO on all errors. The
	/// resource manager will take responsibility of zeroing out any temporary
	/// APDU buffers for security reasons.
	/// @param[out] RecvPci contains two structure members
	/// - Protocol - 0, 1, ... 14\\n
	/// T=0 ... T=14
	/// - Length\\n
	/// Not used.
	///
	/// @note
	/// The driver is responsible for knowing what type of card it has. If the
	/// current slot/card contains a memory card then this command should ignore
	/// the Protocol and use the MCT style commands for support for these style
	/// cards and transmit them appropriately. If your reader does not support
	/// memory cards or you don't want to implement this functionality, then
	/// ignore this.
	/// @par
	/// RxLength should be set to zero on error.
	/// @par
	/// The driver is not responsible for doing an automatic Get Response
	/// command for received buffers containing 61 XX.
	///
	/// @return Error codes
	/// @retval IFD_SUCCESS Successful (\\ref IFD_SUCCESS)
	/// @retval IFD_COMMUNICATION_ERROR Error has occurred (\\ref IFD_COMMUNICATION_ERROR)
	/// @retval IFD_RESPONSE_TIMEOUT The response timed out (\\ref IFD_RESPONSE_TIMEOUT)
	/// @retval IFD_ICC_NOT_PRESENT ICC is not present (\\ref IFD_ICC_NOT_PRESENT)
	/// @retval IFD_NOT_SUPPORTED Action not supported (\\ref IFD_NOT_SUPPORTED)
	/// @retval IFD_NO_SUCH_DEVICE The reader is no more present (\\ref IFD_NO_SUCH_DEVICE)
	pub(in crate::ifdhandler) fn IFDHTransmitToICC(Lun: DWORD, SendPci: SCARD_IO_HEADER, TxBuffer: *mut u8, TxLength: DWORD, RxBuffer: *mut u8, RxLength: *mut DWORD, RecvPci: *mut SCARD_IO_HEADER) -> RESPONSECODE;
}
