// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// A control code; must be supported by the CCID project driver libccid on Linux and MacOS.
///
/// The CCID project at <https://salsa.debian.org/rousseau/CCID.git> contains a list of control codes in [`SCARDCONTROL.txt`](https://salsa.debian.org/rousseau/CCID/-/blob/master/SCARDCONTOL.txt).
///
/// Direct support is in ifdhandler.c, EXTERNAL RESPONSECODE IFDHControl(DWORD Lun ...)
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct ControlCode(DWORD);

impl ControlCode
{
	/// Smart card vendor Interface Device (IFD) exchange.
	///
	/// See `def switch_interface` in PCSC lite `control_switch_interface.py`.
	///
	/// The send buffer is sent as a `PC_to_RDR_Escape` CCID command.
	///
	/// For security this command in possible in the following cases only:-
	///  * the `ifdDriverOptions` (in the `Info.plist` file) has the bit `DRIVER_OPTION_CCID_EXCHANGE_AUTHORIZED` set.
	/// * the reader is a Gemalto (ex Gemplus) reader and the command is:-
	/// 	* get firmware version.
	/// 	* switch interface on a ProxDU.
	pub const VendorInterfaceDevice: Self = Self(IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE);
	
	/// Implements the Implements the PC/SC v2.02.08 Part 10 IOCTL mechanism.
	pub const GetFeatureRequest: Self = Self(CM_IOCTL_GET_FEATURE_REQUEST);
	
	/// See PC/SC v2.02.08 Part 10.
	///
	/// Check the control `GetFeatureRequest` first.
	pub const FeatureVerifyPinDirect: Self = Self(IOCTL_FEATURE_VERIFY_PIN_DIRECT);
	
	/// See PC/SC v2.02.08 Part 10.
	///
	/// Check the control `GetFeatureRequest` first.
	pub const FeatureModifyPinDirect: Self = Self(IOCTL_FEATURE_MODIFY_PIN_DIRECT);
	
	/// See PC/SC v2.02.08 Part 10.
	///
	/// Check the control `GetFeatureRequest` first.
	pub const FeatureMultifunctionalCardTerminalReaderDirect: Self = Self(IOCTL_FEATURE_MCT_READER_DIRECT);
	
	/// See PC/SC v2.02.08 Part 10.
	///
	/// Check the control `GetFeatureRequest` first.
	pub const FeatureInterfaceDevicePinProperties: Self = Self(IOCTL_FEATURE_IFD_PIN_PROPERTIES);
	
	/// See PC/SC v2.02.08 Part 10.
	///
	/// Check the control `GetFeatureRequest` first.
	pub const GetTagLengthValueProperties: Self = Self(IOCTL_FEATURE_GET_TLV_PROPERTIES);
	
	#[inline(always)]
	const fn into_DWORD(self) -> DWORD
	{
		self.0
	}
}
