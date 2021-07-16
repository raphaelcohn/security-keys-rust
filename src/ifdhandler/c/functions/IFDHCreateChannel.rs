// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// This function is required to open a communications channel to the port
	/// listed by Channel. For example, the first serial reader on COM1 would
	/// link to @p /dev/pcsc/1 which would be a symbolic link to @p /dev/ttyS0
	/// on some machines This is used to help with inter-machine independence.
	///
	/// On machines with no /dev directory the driver writer may choose to map
	/// their Channel to whatever they feel is appropriate.
	///
	/// Once the channel is opened the reader must be in a state in which it is
	/// possible to query IFDHICCPresence() for card status.
	///
	/// USB readers can ignore the @p Channel parameter and query the USB bus
	/// for the particular reader by manufacturer and product id.
	///
	/// @ingroup IFDHandler
	/// @param[in] Lun Logical Unit Number\\n
	/// Use this for multiple card slots or multiple readers. 0xXXXXYYYY -
	/// XXXX multiple readers, YYYY multiple slots. The resource manager will
	/// set these automatically. By default the resource manager loads a new
	/// instance of the driver so if your reader does not have more than one
	/// smart card slot then ignore the Lun in all the functions.\\n
	/// \\n
	/// PC/SC supports the loading of multiple readers through one instance of
	/// the driver in which XXXX is important. XXXX identifies the unique
	/// reader in which the driver communicates to. The driver should set up
	/// an array of structures that associate this XXXX with the underlying
	/// details of the particular reader.
	/// @param[in] Channel Channel ID
	/// This is denoted by the following:
	/// - 0x000001 \t@p /dev/pcsc/1
	/// - 0x000002 \t@p /dev/pcsc/2
	/// - 0x000003 \t@p /dev/pcsc/3
	/// - 0x000004 \t@p /dev/pcsc/4
	///
	/// @return Error codes
	/// @retval IFD_SUCCESS Successful (\\ref IFD_SUCCESS)
	/// @retval IFD_COMMUNICATION_ERROR Error has occurred (\\ref IFD_COMMUNICATION_ERROR)
	/// @retval IFD_NO_SUCH_DEVICE The reader is no more present (\\ref IFD_NO_SUCH_DEVICE)
	///
	pub(in crate::ifdhandler) fn IFDHCreateChannel(Lun: DWORD, Channel: DWORD) -> RESPONSECODE;
}
