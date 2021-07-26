// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// `#[repr(DWORD)]`.
///
/// The CCID project at <https://salsa.debian.org/rousseau/CCID.git> contains a partial list of attribute value formats in [`SCARDGETATTRIB.txt`](https://salsa.debian.org/rousseau/CCID/-/blob/master/SCARDGETATTRIB.txt).
#[cfg_attr(any(target_os = "ios", target_os = "macos", target_os = "windows"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "ios", target_os = "macos", target_os = "windows")), target_pointer_width = "32"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "ios", target_os = "macos", target_os = "windows")), target_pointer_width = "64"), repr(u64))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum AttributeIdentifier
{
	/// Supported by libccid for get.
	///
	/// Answer-to-Reset (`ATR`) string.
	///
	/// Despite being called a string, sample code in the PCSC lite project implies there is no terminating null byte.
	///
	/// The maximum attribute_value buffer length is `MAX_ATR_SIZE`.
	AnswerToResetString = SCARD_ATTR_ATR_STRING,
	
	/// Supported by libccid for get.
	///
	/// Single byte.
	///
	/// * `0`: smart card electrical contact is not active.
	/// * `1`: smart card electrical contact is active.
	/// * non-zero: smart card electrical contact is active (Windows).
	IccInterfaceStatus = SCARD_ATTR_ICC_INTERFACE_STATUS,
	
	/// Supported by libccid for get.
	///
	/// Single byte.
	///
	/// On libccid:-
	///
	/// * `0`: not present.
	/// * `2`: card present (and swallowed if reader supports smart card swallowing).
	///
	/// On Windows, the following are also supported:-
	///
	/// * `1`: card present but not swallowed (applies only if reader supports smart card swallowing).
	/// * `4`: card confiscated.
	IccPresence = SCARD_ATTR_ICC_PRESENCE,
	
	/// Supported by libccid for get.
	///
	/// Vendor-supplied Interface Device (IFD) version.
	///
	/// Derived from the USB field `bcdDevice`.
	///
	/// A native-endian `u32` (not DWORD, despite documentation in libccid) in the form `0xMMmmbbbb` where:-
	///
	/// * `MM`: major version.
	/// * `mm`: minor version.
	/// * `bbbb`: build number.
	VendorInterfaceDeviceVersion = SCARD_ATTR_VENDOR_IFD_VERSION,
	
	/// Supported by libccid for get.
	///
	/// Vendor name as an ASCII NULL terminated C String.
	///
	/// Derived from the USB field `iManufacturer` if present.
	/// If not present, an empty buffer (*not* an empty C String) is returned, ie the buffer is length 0, not length 1.
	VendorName = SCARD_ATTR_VENDOR_NAME,
	
	/// Supported by libccid for get.
	///
	/// Maximum size of an Application Protocol Data Unit (APDU) supported by the card reader.
	///
	/// A native-endian `u32`.
	///
	/// Card readers should support a value of at least 261 bytes (`CLA` + `INS` + `P1` + `P2` + `Lc` of 255 bytes), but some badly behaved card readers support less.
	///
	/// Card readers that are badly behaved are problematic for the `T = 0` protocol particularly.
	MaximumApplicationProtocolDataUnitSendBufferSize = SCARD_ATTR_MAXINPUT,
	
	/// Supported by libccid for get.
	///
	/// Vendor-supplied Interface Device (IFD) serial number as an ASCII NULL terminated C String.
	///
	/// Derived from the USB field `?` if present.
	/// If not present, an empty buffer (*not* an empty C String) is returned, ie the buffer is length 0, not length 1.
	VendorInterfaceDeviceSerialNumber = SCARD_ATTR_VENDOR_IFD_SERIAL_NO,
	
	/// A native-endian `u32` in the form `0xDDDDCCCC` where:-
	///
	/// * `DDDD` is the data channel type.
	/// * `CCCC` is the data channel number.
	///
	/// `DDDD` is `0x0020` for USB devices, in which case the high byte of `CC` is an USB bus number and the low byte is the USB device address.
	///
	/// Values other than `0x0020` are not supported.
	ChannelIdentifier = SCARD_ATTR_CHANNEL_ID,
	
	/// *NOT SUPPORTED BY libccid*.
	/// 
	/// Vendor-supplied Interface Device (IFD) type; the model designation of the card reader.
	VendorInterfaceDeviceType = SCARD_ATTR_VENDOR_IFD_TYPE,
	
	/// *NOT SUPPORTED BY libccid*.
	AsynchrononousProtocolTypes = SCARD_ATTR_ASYNC_PROTOCOL_TYPES,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Default clock rate, in kHz.
	DefaultClockRateKHz = SCARD_ATTR_DEFAULT_CLK,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Maximum clock rate, in kHz.
	MaximumClockRateKHz = SCARD_ATTR_MAX_CLK,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Default data rate, in bps.
	DefaultDataRateBps = SCARD_ATTR_DEFAULT_DATA_RATE,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Maximum data rate, in bps.
	MaximumDataRateBps = SCARD_ATTR_MAX_DATA_RATE,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Maximum bytes for Information File Size Device (IFSD).
	MaximumInformationFileSizeDevice = SCARD_ATTR_MAX_IFSD,
	
	/// *NOT SUPPORTED BY libccid*.
	SynchronizeProtocolTypes = SCARD_ATTR_SYNC_PROTOCOL_TYPES,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Zero if device does not support power down while smart card is inserted.
	/// Nonzero otherwise.
	PowerManagementSupport = SCARD_ATTR_POWER_MGMT_SUPPORT,
	
	/// *NOT SUPPORTED BY libccid*.
	UserToCardAuthenticationDevice = SCARD_ATTR_USER_TO_CARD_AUTH_DEVICE,
	
	/// *NOT SUPPORTED BY libccid*.
	UserAuthenticationInputDevice = SCARD_ATTR_USER_AUTH_INPUT_DEVICE,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// DWORD indicating which mechanical characteristics are supported.
	/// If zero, no special characteristics are supported.
	/// Note that multiple bits can be set.
	Characteristics = SCARD_ATTR_CHARACTERISTICS,
	
	/// *NOT SUPPORTED BY libccid*.
	CurrentProtocolType = SCARD_ATTR_CURRENT_PROTOCOL_TYPE,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Current clock rate, in kHz.
	CurrentClockRateKHz = SCARD_ATTR_CURRENT_CLK,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Clock conversion factor.
	CurrentClockConversionFactor = SCARD_ATTR_CURRENT_F,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Bit rate conversion factor.
	CurrentBitRateConversionFactor = SCARD_ATTR_CURRENT_D,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Current guard time.
	CurrentGuardTime = SCARD_ATTR_CURRENT_N,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Current work waiting time.
	CurrentWorkWaitingTime = SCARD_ATTR_CURRENT_W,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Current byte size for Information File Size Card (IFSC).
	CurrentInformationFileSizeCardByteSize = SCARD_ATTR_CURRENT_IFSC,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Current byte size for Information File Size Device (IFSD).
	CurrentInformationFileSizeDeviceByteSize = SCARD_ATTR_CURRENT_IFSD,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Current block waiting time.
	CurrentBlockWaitingTime = SCARD_ATTR_CURRENT_BWT,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Current character waiting time.
	CurrentCharacterWaitingTime = SCARD_ATTR_CURRENT_CWT,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Current error block control encoding.
	CurrentErrorBlockControlEncoding = SCARD_ATTR_CURRENT_EBC_ENCODING,
	
	/// *NOT SUPPORTED BY libccid*.
	ExtendedBlockWaitingTime = SCARD_ATTR_EXTENDED_BWT,
	
	/// *NOT SUPPORTED BY libccid*.
	CurrentInputOutputState = SCARD_ATTR_CURRENT_IO_STATE,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Single byte indicating smart card type.
	IccTypePerAnswerToReset = SCARD_ATTR_ICC_TYPE_PER_ATR,
	
	/// *NOT SUPPORTED BY libccid*.
	EscapeReset = SCARD_ATTR_ESC_RESET,
	
	/// *NOT SUPPORTED BY libccid*.
	EscapeCancel = SCARD_ATTR_ESC_CANCEL,
	
	/// *NOT SUPPORTED BY libccid*.
	EscapeAuthenticationRequest = SCARD_ATTR_ESC_AUTHREQUEST,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Instance of this vendor's reader attached to the computer.
	/// The first instance will be device unit 0, the next will be unit 1 (if it is the same brand of reader) and so on.
	/// Two different brands of readers will both have zero for this value.
	DeviceUnit = SCARD_ATTR_DEVICE_UNIT,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Reserved for future use.
	DeviceInUse = SCARD_ATTR_DEVICE_IN_USE,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Reader's display name.
	DeviceFriendlyName = SCARD_ATTR_DEVICE_FRIENDLY_NAME_A,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Reader's system name.
	DeviceSystemName = SCARD_ATTR_DEVICE_SYSTEM_NAME_A,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Reader's display name (Windows-wide char).
	#[cfg(target_os = "windows")]
	DeviceFriendlyNameWindowsWide = SCARD_ATTR_DEVICE_FRIENDLY_NAME_W,
	
	/// *NOT SUPPORTED BY libccid*.
	///
	/// Reader's system name (Windows-wide char).
	#[cfg(target_os = "windows")]
	DeviceSystemNameWindowsWide = SCARD_ATTR_DEVICE_SYSTEM_NAME_W,
	
	/// *NOT SUPPORTED BY libccid*.
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
