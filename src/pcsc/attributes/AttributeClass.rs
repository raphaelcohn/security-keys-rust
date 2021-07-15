// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// `#[repr(DWORD)]`.
#[cfg_attr(any(target_os = "macos", target_os = "windows"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "32"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "64"), repr(u64))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) enum AttributeClass
{
	#[allow(dead_code)]
	VendorInformation = SCARD_CLASS_VENDOR_INFO,
	
	#[allow(dead_code)]
	Communications = SCARD_CLASS_COMMUNICATIONS,
	
	#[allow(dead_code)]
	Protocol = SCARD_CLASS_PROTOCOL,
	
	#[allow(dead_code)]
	PowerManagement = SCARD_CLASS_POWER_MGMT,
	
	#[allow(dead_code)]
	Security = SCARD_CLASS_SECURITY,
	
	#[allow(dead_code)]
	Mechanical = SCARD_CLASS_MECHANICAL,
	
	#[allow(dead_code)]
	VendorDefined = SCARD_CLASS_VENDOR_DEFINED,
	
	#[allow(dead_code)]
	IfdProtocol = SCARD_CLASS_IFD_PROTOCOL,
	
	#[allow(dead_code)]
	IccState = SCARD_CLASS_ICC_STATE,
	
	#[allow(dead_code)]
	System = SCARD_CLASS_SYSTEM,
}
