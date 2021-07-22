// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// ***Only one thread at a time can call this for a particular `Lun`.***.
	///
	/// This function performs a data exchange with the reader (not the card) specified by `Lun`.
	/// It is responsible for abstracting functionality such as PIN pads, biometrics, LCD panels, etc.
	/// You should follow the MCT (Multifunctional Card Terminal) and CTBCS specifications for a list of accepted commands to implement.
	/// This function is fully voluntary and does not have to be implemented unless you want extended functionality.
	///
	/// * `Lun`:  Logical Unit Number, also called `slot`.
	/// * `dwControlCode`:  Control code for the operation. This value identifies the specific operation to be performed. This value is driver specific.
	/// * `TxBuffer`:  Transmit data
	/// * `TxLength`:  Length of this buffer.
	/// * `RxBuffer`:  Receive data.
	/// * `RxLength`:  Length of the response buffer.
	/// * `pdwBytesReturned`:  Length of response.
	///
	/// This function will be passed the length of the buffer `RxBuffer` in `RxLength` and it must set the length of the received data in `pdwBytesReturned`.
	/// On error, `pdwBytesReturned` should be set to zero.
	///
	///
	/// ## Control codes supported by the ifd-ccd.bundle driver.
	///
	/// * `IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE`: Only if the driver option `DRIVER_OPTION_CCID_EXCHANGE_AUTHORIZED` is specified in the ifdDriverOptions in Info.plist.
	///* `CM_IOCTL_GET_FEATURE_REQUEST`  / `0x313520`: PC/SC v2.02.07 Part 10: Query for features.
	///* `IOCTL_FEATURE_IFD_PIN_PROPERTIES`: PC/SC v2.02.07 Part 10: Get PIN handling capabilities.
	///* `IOCTL_FEATURE_GET_TLV_PROPERTIES`: PC/SC v2.02.07 Part 10: Reader features.
	///* `IOCTL_FEATURE_VERIFY_PIN_DIRECT`: PC/SC v2.02.07 Part 10: Verify a PIN.
	///* `IOCTL_FEATURE_MODIFY_PIN_DIRECT`: PC/SC v2.02.07 Part 10: Modify a PIN.
	///* `IOCTL_FEATURE_MCT_READER_DIRECT`: PC/SC v2.02.07 Part 10: Multifunctional Card Terminal. The transmit buffer contains an Application Protocol Data Unit (APDU).
	///
	///
	/// ## Multifunctional Card Terminal Application Protocol Data Unit (APDU).
	///
	/// * `CLA`: `0x20`.
	/// * `INS`:  One of:-
	/// 	* `0x70`: `SECODER INFO`.
	/// 	* `0x71`: `SECODER SELECT APPLICATION`.
	/// 	* `0x72`: `SECODER APPLICATION ACTIVE`.
	/// 	* `0x73`: `SECODER DATA CONFIRMATION`.
	/// 	* `0x74`: `SECODER PROCESS AUTHENTICATION TOKEN`.
	/// * `P1`: `0x00`.
	/// * `P2`: `0x00`.
	/// * `Lind`: `0x00`.
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	/// * `IFD_RESPONSE_TIMEOUT`: The response timed out.
	pub(in crate::ifdhandler) fn IFDHControl(Lun: DWORD, dwControlCode: DWORD, TxBuffer: *mut u8, TxLength: DWORD, RxBuffer: *mut u8, RxLength: DWORD, pdwBytesReturned: *mut DWORD) -> RESPONSECODE;
}
