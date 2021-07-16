// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


extern "C"
{
	/// This function controls the power and reset signals of the smart card
	/// reader at the particular reader/slot specified by @p Lun.
	///
	/// @ingroup IFDHandler
	/// @param[in] Lun Logical Unit Number
	/// @param[in] Action Action to be taken on the card
	/// - \\ref IFD_POWER_UP
	/// Power up the card (store and return Atr and AtrLength)
	/// - \\ref IFD_POWER_DOWN
	/// Power down the card (Atr and AtrLength should be zeroed)
	/// - \\ref IFD_RESET
	/// Perform a warm reset of the card (no power down). If the card is not powered then power up the card (store and return Atr and AtrLength)
	/// @param[out] Atr Answer to Reset (ATR) of the card\\n
	/// The driver is responsible for caching this value in case
	/// IFDHGetCapabilities() is called requesting the ATR and its length. The
	/// ATR length should not exceed \\ref MAX_ATR_SIZE.
	/// @param[in,out] AtrLength Length of the ATR\\n
	/// This should not exceed \\ref MAX_ATR_SIZE.
	///
	/// @note
	/// Memory cards without an ATR should return \\ref IFD_SUCCESS on reset but the
	/// Atr should be zeroed and the length should be zero Reset errors should
	/// return zero for the AtrLength and return \\ref IFD_ERROR_POWER_ACTION.
	///
	/// @return Error codes
	/// @retval IFD_SUCCESS Successful (\\ref IFD_SUCCESS)
	/// @retval IFD_ERROR_POWER_ACTION Error powering/resetting card (\\ref IFD_ERROR_POWER_ACTION)
	/// @retval IFD_COMMUNICATION_ERROR Error has occurred (\\ref IFD_COMMUNICATION_ERROR)
	/// @retval IFD_NOT_SUPPORTED Action not supported (\\ref IFD_NOT_SUPPORTED)
	/// @retval IFD_NO_SUCH_DEVICE The reader is no more present (\\ref IFD_NO_SUCH_DEVICE)
	pub(in crate::ifdhandler) fn IFDHPowerICC(Lun: DWORD, Action: DWORD, Atr: *mut u8, AtrLength: *mut DWORD) -> RESPONSECODE;
}
