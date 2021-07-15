// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// `#[repr(DWORD)]`.
#[cfg_attr(any(target_os = "macos", target_os = "windows"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "32"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "64"), repr(u64))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum AttributeIdentifier
{
	/// Vendor name.
	VendorName = SCARD_ATTR_VENDOR_NAME,
	
	/// Vendor-supplied Interface Device (IFD) type; the model designation of the card reader.
	VendorInterfaceDeviceType = SCARD_ATTR_VENDOR_IFD_TYPE,
	
	/// Vendor-supplied Interface Device (IFD) version (DWORD in the form 0xMMmmbbbb where MM = major version, mm = minor version, and bbbb = build number).
	VendorInterfaceDeviceVersion = SCARD_ATTR_VENDOR_IFD_VERSION,
	
	/// Vendor-supplied Interface Device (IFD) serial number.
	VendorInterfaceDeviceSerialNumber = SCARD_ATTR_VENDOR_IFD_SERIAL_NO,
	
	/// DWORD encoded as 0xDDDDCCCC, where DDDD = data channel type and CCCC = channel number.
	ChannelIdentifier = SCARD_ATTR_CHANNEL_ID,
	
	#[allow(missing_docs)]
	AsynchrononousProtocolTypes = SCARD_ATTR_ASYNC_PROTOCOL_TYPES,
	
	/// Default clock rate, in kHz.
	DefaultClockRateKHz = SCARD_ATTR_DEFAULT_CLK,
	
	/// Maximum clock rate, in kHz.
	MaximumClockRateKHz = SCARD_ATTR_MAX_CLK,
	
	/// Default data rate, in bps.
	DefaultDataRateBps = SCARD_ATTR_DEFAULT_DATA_RATE,
	
	/// Maximum data rate, in bps.
	MaximumDataRateBps = SCARD_ATTR_MAX_DATA_RATE,
	
	/// Maximum bytes for Information File Size Device (IFSD).
	MaximumInformationFileSizeDevice = SCARD_ATTR_MAX_IFSD,
	
	#[allow(missing_docs)]
	SynchronizeProtocolTypes = SCARD_ATTR_SYNC_PROTOCOL_TYPES,
	
	/// Zero if device does not support power down while smart card is inserted.
	/// Nonzero otherwise.
	PowerManagementSupport = SCARD_ATTR_POWER_MGMT_SUPPORT,
	
	#[allow(missing_docs)]
	UserToCardAuthenticationDevice = SCARD_ATTR_USER_TO_CARD_AUTH_DEVICE,
	
	#[allow(missing_docs)]
	UserAuthenticationInputDevice = SCARD_ATTR_USER_AUTH_INPUT_DEVICE,
	
	/// DWORD indicating which mechanical characteristics are supported.
	/// If zero, no special characteristics are supported.
	/// Note that multiple bits can be set.
	Characteristics = SCARD_ATTR_CHARACTERISTICS,
	
	#[allow(missing_docs)]
	CurrentProtocolType = SCARD_ATTR_CURRENT_PROTOCOL_TYPE,
	
	/// Current clock rate, in kHz.
	CurrentClockRateKHz = SCARD_ATTR_CURRENT_CLK,
	
	/// Clock conversion factor.
	CurrentClockConversionFactor = SCARD_ATTR_CURRENT_F,
	
	/// Bit rate conversion factor.
	CurrentD = SCARD_ATTR_CURRENT_D,
	
	/// Current guard time.
	CurrentN = SCARD_ATTR_CURRENT_N,
	
	/// Current work waiting time.
	CurrentW = SCARD_ATTR_CURRENT_W,
	
	/// Current byte size for Information File Size Card (IFSC).
	CurrentInformationFileSizeCardByteSize = SCARD_ATTR_CURRENT_IFSC,
	
	/// Current byte size for Information File Size Device (IFSD).
	CurrentInformationFileSizeDeviceByteSize = SCARD_ATTR_CURRENT_IFSD,
	
	/// Current block waiting time.
	CurrentBlockWaitingTime = SCARD_ATTR_CURRENT_BWT,
	
	/// Current character waiting time.
	CurrentCharacterWaitingTime = SCARD_ATTR_CURRENT_CWT,
	
	/// Current error block control encoding.
	CurrentErrorBlockControlEncoding = SCARD_ATTR_CURRENT_EBC_ENCODING,
	
	#[allow(missing_docs)]
	ExtendedBlockWaitingTime = SCARD_ATTR_EXTENDED_BWT,
	
	/// Single byte indicating smart card presence.
	IccPresence = SCARD_ATTR_ICC_PRESENCE,
	
	/// Single byte.
	/// Zero if smart card electrical contact is not active; nonzero if contact is active.
	#[allow(missing_docs)]
	IccInterfaceStatus = SCARD_ATTR_ICC_INTERFACE_STATUS,
	
	#[allow(missing_docs)]
	CurrentInputOutputState = SCARD_ATTR_CURRENT_IO_STATE,
	
	/// Answer-to-Reset (`ATR`) string.
	AnswerToResetString = SCARD_ATTR_ATR_STRING,
	
	/// Single byte indicating smart card type.
	IccTypePerAnswerToReset = SCARD_ATTR_ICC_TYPE_PER_ATR,
	
	#[allow(missing_docs)]
	EscapeReset = SCARD_ATTR_ESC_RESET,
	
	#[allow(missing_docs)]
	EscapeCancel = SCARD_ATTR_ESC_CANCEL,
	
	#[allow(missing_docs)]
	EscapeAuthenticationRequest = SCARD_ATTR_ESC_AUTHREQUEST,
	
	#[allow(missing_docs)]
	MaximumInput = SCARD_ATTR_MAXINPUT,
	
	/// Instance of this vendor's reader attached to the computer.
	/// The first instance will be device unit 0, the next will be unit 1 (if it is the same brand of reader) and so on.
	/// Two different brands of readers will both have zero for this value.
	#[allow(missing_docs)]
	DeviceUnit = SCARD_ATTR_DEVICE_UNIT,
	
	/// Reserved for future use.
	#[allow(missing_docs)]
	DeviceInUse = SCARD_ATTR_DEVICE_IN_USE,
	
	/// Reader's display name.
	#[allow(missing_docs)]
	DeviceFriendlyName = SCARD_ATTR_DEVICE_FRIENDLY_NAME_A,
	
	/// Reader's system name.
	#[allow(missing_docs)]
	DeviceSystemName = SCARD_ATTR_DEVICE_SYSTEM_NAME_A,
	
	/// Reader's display name (Windows-wide char).
	#[cfg(target_os = "windows")]
	DeviceFriendlyNameWindowsWide = SCARD_ATTR_DEVICE_FRIENDLY_NAME_W,
	
	/// Reader's system name (Windows-wide char).
	#[cfg(target_os = "windows")]
	DeviceSystemNameWindowsWide = SCARD_ATTR_DEVICE_SYSTEM_NAME_W,
	
	#[allow(missing_docs)]
	SupressT1ProtocolIFSRequest = SCARD_ATTR_SUPRESS_T1_IFS_REQUEST,
}

impl AttributeIdentifier
{
	#[inline(always)]
	pub(in crate::pcsc) const fn into_DWORD(self) -> DWORD
	{
		unsafe { transmute(self) }
	}
	
	/// Class.
	#[inline(always)]
	pub fn class(self) -> AttributeClass
	{
		unsafe { transmute(self.into_DWORD() >> AttributeClassShift) }
	}
}
