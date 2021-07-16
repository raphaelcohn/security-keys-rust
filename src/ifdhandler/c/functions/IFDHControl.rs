// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// This function performs a data exchange with the reader (not the card)
	/// specified by Lun. It is responsible for abstracting functionality such
	/// as PIN pads, biometrics, LCD panels, etc. You should follow the MCT and
	/// CTBCS specifications for a list of accepted commands to implement. This
	/// function is fully voluntary and does not have to be implemented unless
	/// you want extended functionality.
	///
	/// @ingroup IFDHandler
	/// @param[in] Lun Logical Unit Number
	/// @param[in] dwControlCode Control code for the operation\\n
	/// This value identifies the specific operation to be performed. This
	/// value is driver specific.
	/// @param[in] TxBuffer Transmit data
	/// @param[in] TxLength Length of this buffer
	/// @param[out] RxBuffer Receive data
	/// @param[in] RxLength Length of the response buffer
	/// @param[out] pdwBytesReturned Length of response\\n
	/// This function will be passed the length of the buffer RxBuffer in
	/// RxLength and it must set the length of the received data in
	/// pdwBytesReturned.
	///
	/// @note
	/// @p *pdwBytesReturned should be set to zero on error.
	///
	/// @return Error codes
	/// @retval IFD_SUCCESS Successful (\\ref IFD_SUCCESS)
	/// @retval IFD_COMMUNICATION_ERROR Error has occurred (\\ref IFD_COMMUNICATION_ERROR)
	/// @retval IFD_RESPONSE_TIMEOUT The response timed out (\\ref IFD_RESPONSE_TIMEOUT)
	/// @retval IFD_NO_SUCH_DEVICE The reader is no more present (\\ref IFD_NO_SUCH_DEVICE)
	pub(in crate::ifdhandler) fn IFDHControl(Lun: DWORD, dwControlCode: DWORD, TxBuffer: *mut u8, TxLength: DWORD, RxBuffer: *mut u8, RxLength: DWORD, pdwBytesReturned: *mut DWORD) -> RESPONSECODE;
}
