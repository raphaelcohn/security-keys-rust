// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// This function should set the slot/card capabilities for a particular
	/// slot/card specified by @p Lun. Again, if you have only 1 card slot and
	/// don't mind loading a new driver for each reader then ignore @p Lun.
	///
	/// @ingroup IFDHandler
	/// @param[in] Lun Logical Unit Number
	/// @param[in] Tag Tag of the desired data value
	/// @param[in,out] Length Length of the desired data value
	/// @param[out] Value Value of the desired data
	///
	/// This function is also called when the application uses the PC/SC
	/// SCardSetAttrib() function. The list of supported tags is not limited.
	///
	/// @return Error codes
	/// @retval IFD_SUCCESS Successful (\\ref IFD_SUCCESS)
	/// @retval IFD_ERROR_TAG Invalid tag given (\\ref IFD_ERROR_TAG)
	/// @retval IFD_ERROR_SET_FAILURE Could not set value (\\ref IFD_ERROR_SET_FAILURE)
	/// @retval IFD_ERROR_VALUE_READ_ONLY Trying to set read only value (\\ref IFD_ERROR_VALUE_READ_ONLY)
	/// @retval IFD_NO_SUCH_DEVICE The reader is no more present (\\ref IFD_NO_SUCH_DEVICE)
	pub(in crate::ifdhandler) fn IFDHSetCapabilities(Lun: DWORD, Tag: DWORD, Length: DWORD, Value: *mut u8) -> RESPONSECODE;
}
