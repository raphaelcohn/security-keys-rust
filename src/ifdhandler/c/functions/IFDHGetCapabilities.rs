// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// This function should get the slot/card capabilities for a particular
	/// slot/card specified by Lun. Again, if you have only 1 card slot and
	/// don't mind loading a new driver for each reader then ignore Lun.
	///
	/// @ingroup IFDHandler
	/// @param[in] Lun Logical Unit Number
	/// @param[in] Tag Tag of the desired data value
	/// - \\ref TAG_IFD_ATR
	/// Return the ATR and its size (implementation is mandatory).
	/// - \\ref TAG_IFD_SLOTNUM
	/// Unused/deprecated
	/// - \\ref SCARD_ATTR_ATR_STRING
	/// Same as \\ref TAG_IFD_ATR but this one is not mandatory. It is defined
	/// in Microsoft PC/SC SCardGetAttrib().
	/// - \\ref TAG_IFD_SIMULTANEOUS_ACCESS
	/// Return the number of sessions (readers) the driver can handle in
	/// <tt>Value[0]</tt>.
	/// This is used for multiple readers sharing the same driver.
	/// - \\ref TAG_IFD_THREAD_SAFE
	/// If the driver supports more than one reader (see
	/// \\ref TAG_IFD_SIMULTANEOUS_ACCESS above) this tag indicates if the
	/// driver supports access to multiple readers at the same time.
	/// - <tt>Value[0] = 0</tt>: the driver DOES NOT support simultaneous accesses.
	/// - <tt>Value[0] = 1</tt>: the driver supports simultaneous accesses.
	/// - \\ref TAG_IFD_SLOTS_NUMBER
	/// Return the number of slots in this reader in <tt>Value[0]</tt>.
	/// - \\ref TAG_IFD_SLOT_THREAD_SAFE
	/// If the reader has more than one slot (see \\ref TAG_IFD_SLOTS_NUMBER
	/// above) this tag indicates if the driver supports access to multiple
	/// slots of the same reader at the same time.
	/// - <tt>value[0] = 0</tt>: the driver supports only 1 slot access at a time.
	/// - <tt>value[0] = 1</tt>: the driver supports simultaneous slot accesses.
	/// - \\ref TAG_IFD_POLLING_THREAD
	/// Unused/deprecated
	/// - \\ref TAG_IFD_POLLING_THREAD_WITH_TIMEOUT
	/// If the driver provides a polling thread then @p Value is a pointer to
	/// this function. The function prototype is:
	/// @verbatim
	/// RESPONSECODE foo(DWORD Lun, int timeout);
	/// @endverbatim
	/// - \\ref TAG_IFD_POLLING_THREAD_KILLABLE
	/// Tell if the polling thread can be killed (pthread_kill()) by pcscd
	/// - <tt>value[0] = 0</tt>: the driver can NOT be stopped using
	/// pthread_cancel(). The driver must then implement
	/// \\ref TAG_IFD_STOP_POLLING_THREAD
	/// - <tt>value[0] = 1</tt>: the driver can be stopped using pthread_cancel()
	/// - \\ref TAG_IFD_STOP_POLLING_THREAD
	/// Returns a pointer in @p Value to the function used to stop the polling
	/// thread returned by \\ref TAG_IFD_POLLING_THREAD_WITH_TIMEOUT. The
	/// function prototype is:
	/// @verbatim
	/// RESPONSECODE foo(DWORD Lun);
	/// @endverbatim
	/// @param[in,out] Length Length of the desired data value
	/// @param[out] Value Value of the desired data
	///
	/// @return Error codes
	/// @retval IFD_SUCCESS Successful (\\ref IFD_SUCCESS)
	/// @retval IFD_ERROR_INSUFFICIENT_BUFFER Buffer is too small (\\ref IFD_ERROR_INSUFFICIENT_BUFFER)
	/// @retval IFD_COMMUNICATION_ERROR Error has occurred (\\ref IFD_COMMUNICATION_ERROR)
	/// @retval IFD_ERROR_TAG Invalid tag given (\\ref IFD_ERROR_TAG)
	/// @retval IFD_NO_SUCH_DEVICE The reader is no more present (\\ref IFD_NO_SUCH_DEVICE)
	pub(in crate::ifdhandler) fn IFDHGetCapabilities(Lun: DWORD, Tag: DWORD, Length: *mut DWORD, Value: *mut u8) -> RESPONSECODE;
}
