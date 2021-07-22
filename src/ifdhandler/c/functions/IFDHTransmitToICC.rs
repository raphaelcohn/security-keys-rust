// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// ***Only one thread at a time can call this for a particular `Lun`.***.
	///
	/// This function performs an APDU exchange with the card or slot specified by Lun.
	///
	/// The driver is responsible for performing any protocol specific exchanges such as T=0, 1, etc.
	/// Calling this function will abstract all protocol differences.
	///
	/// * `Lun`: Logical Unit Number.
	/// * `SendPci`: A struct containing a `Protocol` field with a value from `0` to `14` inclusive, and an unused `Length` field.
	/// * `TxBuffer`: A buffer containing a transmit Application Protocol Data Unit (APDU), eg `[0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]`.
	/// * `TxLength`: Length of the `TxBuffer` buffer.
	/// * `RxBuffer`: A buffer to contain a receive Application Protocol Data Unit (APDU), eg `[0x61, 0x14]`.
	/// * `RxLength`: Length of the `RxBuffer` buffer; length of the received receive Application Protocol Data Unit (APDU). Must be zero if an error occurs.
	/// * `RecvPci`:  A struct containing a `Protocol` field with a value from `0` to `14` inclusive, and an unused `Length` field.
	///
	///
	/// ## PCI
	///
	/// In the above function parameters 'Pci' has nothing to do with the PCI interface, but instead stands for Protocol Control Information.
	///
	///
	/// ## Memory Cards
	///
	/// The driver is responsible for knowing what type of card it has.
	/// If the current slot or card contains a memory card then this command should ignore  the Protocol and use the MCT (Multifunctional Card Terminal) style commands for support for these style cards and transmit them appropriately.
	/// If your reader does not support/ memory cards or you don't want to implement this functionality, then ignore this.
	///
	///
	/// ## Get Response Application Protocol Data Unit.
	///
	/// The driver is not responsible for doing an automatic Get Response command for received buffers with a status code of `0x61 0xXX`.
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	/// * `IFD_ICC_NOT_PRESENT`: ICC is not present.
	/// * `IFD_RESPONSE_TIMEOUT`:  The response timed out.
	/// * `IFD_NOT_SUPPORTED`:  ?Transmission of APDUs is unsupported, or the chosen SendPci protocol is not supported?
	pub(in crate::ifdhandler) fn IFDHTransmitToICC(Lun: DWORD, SendPci: SCARD_IO_HEADER, TxBuffer: *const u8, TxLength: DWORD, RxBuffer: *mut u8, RxLength: *mut DWORD, RecvPci: *mut SCARD_IO_HEADER) -> RESPONSECODE;
}
