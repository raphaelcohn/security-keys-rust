// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// `#[repr(DWORD)]`.
#[cfg_attr(any(target_os = "macos", target_os = "windows"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "32"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "64"), repr(u64))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) enum AttributeIdentifier
{
	#[allow(dead_code)]
	VendorName = SCARD_ATTR_VENDOR_NAME,
	
	#[allow(dead_code)]
	VendorIFDType = SCARD_ATTR_VENDOR_IFD_TYPE,
	
	#[allow(dead_code)]
	VendorIFDVersion = SCARD_ATTR_VENDOR_IFD_VERSION,
	
	#[allow(dead_code)]
	VendorIFDSerialNumber = SCARD_ATTR_VENDOR_IFD_SERIAL_NO,
	
	#[allow(dead_code)]
	ChannelIdentifier = SCARD_ATTR_CHANNEL_ID,
	
	#[allow(dead_code)]
	AsynchrononousProtocolTypes = SCARD_ATTR_ASYNC_PROTOCOL_TYPES,
	
	#[allow(dead_code)]
	DefaultClock = SCARD_ATTR_DEFAULT_CLK,
	
	#[allow(dead_code)]
	MaximumClock = SCARD_ATTR_MAX_CLK,
	
	#[allow(dead_code)]
	DefaultDataRate = SCARD_ATTR_DEFAULT_DATA_RATE,
	
	#[allow(dead_code)]
	MaximumDataRate = SCARD_ATTR_MAX_DATA_RATE,
	
	#[allow(dead_code)]
	MaximumIFSD = SCARD_ATTR_MAX_IFSD,
	
	#[allow(dead_code)]
	SynchronizeProtocolTypes = SCARD_ATTR_SYNC_PROTOCOL_TYPES,
	
	#[allow(dead_code)]
	PowerManagementSupport = SCARD_ATTR_POWER_MGMT_SUPPORT,
	
	#[allow(dead_code)]
	UserToCardAuthenticationDevice = SCARD_ATTR_USER_TO_CARD_AUTH_DEVICE,
	
	#[allow(dead_code)]
	UserAuthenticationInputDevice = SCARD_ATTR_USER_AUTH_INPUT_DEVICE,
	
	#[allow(dead_code)]
	Characteristics = SCARD_ATTR_CHARACTERISTICS,
	
	#[allow(dead_code)]
	CurrentProtocolType = SCARD_ATTR_CURRENT_PROTOCOL_TYPE,
	
	#[allow(dead_code)]
	CurrentClock = SCARD_ATTR_CURRENT_CLK,
	
	#[allow(dead_code)]
	CurrentF = SCARD_ATTR_CURRENT_F,
	
	#[allow(dead_code)]
	CurrentD = SCARD_ATTR_CURRENT_D,
	
	#[allow(dead_code)]
	CurrentN = SCARD_ATTR_CURRENT_N,
	
	#[allow(dead_code)]
	CurrentW = SCARD_ATTR_CURRENT_W,
	
	#[allow(dead_code)]
	CurrentIFSC = SCARD_ATTR_CURRENT_IFSC,
	
	#[allow(dead_code)]
	CurrentIFSD = SCARD_ATTR_CURRENT_IFSD,
	
	#[allow(dead_code)]
	CurrentBWT = SCARD_ATTR_CURRENT_BWT,
	
	#[allow(dead_code)]
	CurrentCWT = SCARD_ATTR_CURRENT_CWT,
	
	#[allow(dead_code)]
	CurrentEbcEncoding = SCARD_ATTR_CURRENT_EBC_ENCODING,
	
	#[allow(dead_code)]
	ExtendedBWT = SCARD_ATTR_EXTENDED_BWT,
	
	#[allow(dead_code)]
	IccPresence = SCARD_ATTR_ICC_PRESENCE,
	
	#[allow(dead_code)]
	IccInterfaceStatus = SCARD_ATTR_ICC_INTERFACE_STATUS,
	
	#[allow(dead_code)]
	CurrentInputOutputState = SCARD_ATTR_CURRENT_IO_STATE,
	
	#[allow(dead_code)]
	AtrString = SCARD_ATTR_ATR_STRING,
	
	#[allow(dead_code)]
	IccTypePerAnswerToReset = SCARD_ATTR_ICC_TYPE_PER_ATR,
	
	#[allow(dead_code)]
	EscapeReset = SCARD_ATTR_ESC_RESET,
	
	#[allow(dead_code)]
	EscapeCancel = SCARD_ATTR_ESC_CANCEL,
	
	#[allow(dead_code)]
	EscapeAuthenticationRequest = SCARD_ATTR_ESC_AUTHREQUEST,
	
	#[allow(dead_code)]
	MaximumInput = SCARD_ATTR_MAXINPUT,
	
	#[allow(dead_code)]
	DeviceUnit = SCARD_ATTR_DEVICE_UNIT,
	
	#[allow(dead_code)]
	DeviceInUse = SCARD_ATTR_DEVICE_IN_USE,
	
	#[allow(dead_code)]
	DeviceFriendlyName = SCARD_ATTR_DEVICE_FRIENDLY_NAME,
	
	#[allow(dead_code)]
	DeviceSystemName = SCARD_ATTR_DEVICE_SYSTEM_NAME,
	
	#[allow(dead_code)]
	SupressT1ProtocolIFSRequest = SCARD_ATTR_SUPRESS_T1_IFS_REQUEST,
}

impl AttributeIdentifier
{
	#[inline(always)]
	pub(in crate::pcsc) const fn into_DWORD(self) -> DWORD
	{
		unsafe { transmute(self) }
	}
	
	#[inline(always)]
	pub(crate) fn class(self) -> AttributeClass
	{
		unsafe { transmute(self.into_DWORD() >> AttributeClassShift) }
	}
}
