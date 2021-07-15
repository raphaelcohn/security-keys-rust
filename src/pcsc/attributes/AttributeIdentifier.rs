// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// `#[repr(DWORD)]`.
#[cfg_attr(any(target_os = "macos", target_os = "windows"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "32"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "64"), repr(u64))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum AttributeIdentifier
{
	#[allow(missing_docs)]
	VendorName = SCARD_ATTR_VENDOR_NAME,
	
	#[allow(missing_docs)]
	VendorIFDType = SCARD_ATTR_VENDOR_IFD_TYPE,
	
	#[allow(missing_docs)]
	VendorIFDVersion = SCARD_ATTR_VENDOR_IFD_VERSION,
	
	#[allow(missing_docs)]
	VendorIFDSerialNumber = SCARD_ATTR_VENDOR_IFD_SERIAL_NO,
	
	#[allow(missing_docs)]
	ChannelIdentifier = SCARD_ATTR_CHANNEL_ID,
	
	#[allow(missing_docs)]
	AsynchrononousProtocolTypes = SCARD_ATTR_ASYNC_PROTOCOL_TYPES,
	
	#[allow(missing_docs)]
	DefaultClock = SCARD_ATTR_DEFAULT_CLK,
	
	#[allow(missing_docs)]
	MaximumClock = SCARD_ATTR_MAX_CLK,
	
	#[allow(missing_docs)]
	DefaultDataRate = SCARD_ATTR_DEFAULT_DATA_RATE,
	
	#[allow(missing_docs)]
	MaximumDataRate = SCARD_ATTR_MAX_DATA_RATE,
	
	#[allow(missing_docs)]
	MaximumIFSD = SCARD_ATTR_MAX_IFSD,
	
	#[allow(missing_docs)]
	SynchronizeProtocolTypes = SCARD_ATTR_SYNC_PROTOCOL_TYPES,
	
	#[allow(missing_docs)]
	PowerManagementSupport = SCARD_ATTR_POWER_MGMT_SUPPORT,
	
	#[allow(missing_docs)]
	UserToCardAuthenticationDevice = SCARD_ATTR_USER_TO_CARD_AUTH_DEVICE,
	
	#[allow(missing_docs)]
	UserAuthenticationInputDevice = SCARD_ATTR_USER_AUTH_INPUT_DEVICE,
	
	#[allow(missing_docs)]
	Characteristics = SCARD_ATTR_CHARACTERISTICS,
	
	#[allow(missing_docs)]
	CurrentProtocolType = SCARD_ATTR_CURRENT_PROTOCOL_TYPE,
	
	#[allow(missing_docs)]
	CurrentClock = SCARD_ATTR_CURRENT_CLK,
	
	#[allow(missing_docs)]
	CurrentF = SCARD_ATTR_CURRENT_F,
	
	#[allow(missing_docs)]
	CurrentD = SCARD_ATTR_CURRENT_D,
	
	#[allow(missing_docs)]
	CurrentN = SCARD_ATTR_CURRENT_N,
	
	#[allow(missing_docs)]
	CurrentW = SCARD_ATTR_CURRENT_W,
	
	#[allow(missing_docs)]
	CurrentIFSC = SCARD_ATTR_CURRENT_IFSC,
	
	#[allow(missing_docs)]
	CurrentIFSD = SCARD_ATTR_CURRENT_IFSD,
	
	#[allow(missing_docs)]
	CurrentBWT = SCARD_ATTR_CURRENT_BWT,
	
	#[allow(missing_docs)]
	CurrentCWT = SCARD_ATTR_CURRENT_CWT,
	
	#[allow(missing_docs)]
	CurrentEbcEncoding = SCARD_ATTR_CURRENT_EBC_ENCODING,
	
	#[allow(missing_docs)]
	ExtendedBWT = SCARD_ATTR_EXTENDED_BWT,
	
	#[allow(missing_docs)]
	IccPresence = SCARD_ATTR_ICC_PRESENCE,
	
	#[allow(missing_docs)]
	IccInterfaceStatus = SCARD_ATTR_ICC_INTERFACE_STATUS,
	
	#[allow(missing_docs)]
	CurrentInputOutputState = SCARD_ATTR_CURRENT_IO_STATE,
	
	#[allow(missing_docs)]
	AtrString = SCARD_ATTR_ATR_STRING,
	
	#[allow(missing_docs)]
	IccTypePerAnswerToReset = SCARD_ATTR_ICC_TYPE_PER_ATR,
	
	#[allow(missing_docs)]
	EscapeReset = SCARD_ATTR_ESC_RESET,
	
	#[allow(missing_docs)]
	EscapeCancel = SCARD_ATTR_ESC_CANCEL,
	
	#[allow(missing_docs)]
	EscapeAuthenticationRequest = SCARD_ATTR_ESC_AUTHREQUEST,
	
	#[allow(missing_docs)]
	MaximumInput = SCARD_ATTR_MAXINPUT,
	
	#[allow(missing_docs)]
	DeviceUnit = SCARD_ATTR_DEVICE_UNIT,
	
	#[allow(missing_docs)]
	DeviceInUse = SCARD_ATTR_DEVICE_IN_USE,
	
	#[allow(missing_docs)]
	DeviceFriendlyName = SCARD_ATTR_DEVICE_FRIENDLY_NAME,
	
	#[allow(missing_docs)]
	DeviceSystemName = SCARD_ATTR_DEVICE_SYSTEM_NAME,
	
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
