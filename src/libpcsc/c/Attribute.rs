// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// `#[repr(DWORD)]`.
#[cfg_attr(any(target_os = "macos", target_os = "windows"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows"))), target_pointer_width = "32"), repr(u32)]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows"))), target_pointer_width = "64"), repr(u64)]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) enum Attribute
{
	VendorName = SCARD_ATTR_VENDOR_NAME,
	VendorIFDType = SCARD_ATTR_VENDOR_IFD_TYPE,
	VendorIFDVersion = SCARD_ATTR_VENDOR_IFD_VERSION,
	VendorIFDSerialNumber = SCARD_ATTR_VENDOR_IFD_SERIAL_NO,
	ChannelId = SCARD_ATTR_CHANNEL_ID,
	AsynchrononousProtocolTypes = SCARD_ATTR_ASYNC_PROTOCOL_TYPES,
	DefaultClock = SCARD_ATTR_DEFAULT_CLK,
	MaximumClock = SCARD_ATTR_MAX_CLK,
	DefaultDataRate = SCARD_ATTR_DEFAULT_DATA_RATE,
	MaximumDataRate = SCARD_ATTR_MAX_DATA_RATE,
	MaximumIFSD = SCARD_ATTR_MAX_IFSD,
	SynchronizeProtocolTypes = SCARD_ATTR_SYNC_PROTOCOL_TYPES,
	PowerManagementSupport = SCARD_ATTR_POWER_MGMT_SUPPORT,
	UserToCardAuthenticationDevice = SCARD_ATTR_USER_TO_CARD_AUTH_DEVICE,
	UserAuthenticationInputDevice = SCARD_ATTR_USER_AUTH_INPUT_DEVICE,
	Characteristics = SCARD_ATTR_CHARACTERISTICS,
	CurrentProtocolType = SCARD_ATTR_CURRENT_PROTOCOL_TYPE,
	CurrentClock = SCARD_ATTR_CURRENT_CLK,
	CurrentF = SCARD_ATTR_CURRENT_F,
	CurrentD = SCARD_ATTR_CURRENT_D,
	CurrentN = SCARD_ATTR_CURRENT_N,
	CurrentW = SCARD_ATTR_CURRENT_W,
	CurrentIFSC = SCARD_ATTR_CURRENT_IFSC,
	CurrentIFSD = SCARD_ATTR_CURRENT_IFSD,
	CurrentBWT = SCARD_ATTR_CURRENT_BWT,
	CurrentCWT = SCARD_ATTR_CURRENT_CWT,
	CurrentEbcEncoding = SCARD_ATTR_CURRENT_EBC_ENCODING,
	ExtendedBWT = SCARD_ATTR_EXTENDED_BWT,
	IccPresence = SCARD_ATTR_ICC_PRESENCE,
	IccInterfaceStatus = SCARD_ATTR_ICC_INTERFACE_STATUS,
	CurrentInputOutputState = SCARD_ATTR_CURRENT_IO_STATE,
	AtrString = SCARD_ATTR_ATR_STRING,
	IccTypePerAtr = SCARD_ATTR_ICC_TYPE_PER_ATR,
	EscapeReset = SCARD_ATTR_ESC_RESET,
	EscapeCancel = SCARD_ATTR_ESC_CANCEL,
	EscapeAuthenticationRequest = SCARD_ATTR_ESC_AUTHREQUEST,
	MaximumInput = SCARD_ATTR_MAXINPUT,
	DeviceUnit = SCARD_ATTR_DEVICE_UNIT,
	DeviceInUse = SCARD_ATTR_DEVICE_IN_USE,
	DeviceFriendlyName = SCARD_ATTR_DEVICE_FRIENDLY_NAME,
	DeviceSystemName = SCARD_ATTR_DEVICE_SYSTEM_NAME,
	SupressT1ProtocolIFSRequest = SCARD_ATTR_SUPRESS_T1_IFS_REQUEST,
}

impl Attribute
{
	#[inline(always)]
	const fn into_DWORD(self) -> DWORD
	{
		unsafe { transmute(self) }
	}
	
	#[inline(always)]
	fn class(self) -> AttributeClass
	{
		unsafe { transmute(self.into_DWORD() >> AttributeClassShift) }
	}
}
