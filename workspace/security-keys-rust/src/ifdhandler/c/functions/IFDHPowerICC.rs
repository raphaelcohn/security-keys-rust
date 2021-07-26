// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// ***Only one thread at a time can call this for a particular `Lun`.***.
	///
	/// This function controls the power and reset signals of the smart card reader at the particular reader or slot specified by `Lun`.
	///
	/// * `Lun`: Logical Unit Number.
	/// * `Action`: Action to be taken on the card.
	/// * `Atr`: Answer to Reset (`ATR`) of the card. The driver is responsible for caching this value in case `IFDHGetCapabilities()` is called requesting the `ATR` and its length.
	/// * `AtrLength`: Length of the Answer to Reset. This value must not exceed `MAX_ATR_SIZE`.
	///
	///
	/// ## Actions
	///
	/// * `IFD_POWER_UP`: Power up the card (store and return `Atr` and `AtrLength`).
	/// * `IFD_POWER_DOWN`: Power down the card (`Atr` and `AtrLength` should be zeroed).
	/// * `IFD_RESET`:  Perform a warm reset of the card (no power down). If the card is not powered then power up the card (store and return `Atr` and `AtrLength`).
	///
	///
	/// ## Memory cards without an Answer to Reset (`ATR`).
	///
	/// These should return `IFD_SUCCESS` on reset but the `Atr` and `AtrLength` should be zeroed.
	///
	///
	/// ## Reset Errors
	///
	/// These should return zero for the `AtrLength` and return the error code `IFD_ERROR_POWER_ACTION`.
	///
	///
	/// # Return Codes
	///
	/// * `IFD_SUCCESS`: Successful.
	/// * `IFD_COMMUNICATION_ERROR`: Error has occurred.
	/// * `IFD_NO_SUCH_DEVICE`: The reader is no more present.
	/// * `IFD_ERROR_POWER_ACTION`: Error powering or resetting the card.
	/// * `IFD_NOT_SUPPORTED`: Action not supported.
	pub(in crate::ifdhandler) fn IFDHPowerICC(Lun: DWORD, Action: DWORD, Atr: *mut u8, AtrLength: *mut DWORD) -> RESPONSECODE;
}
