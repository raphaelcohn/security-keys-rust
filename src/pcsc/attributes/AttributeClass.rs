// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// `#[repr(DWORD)]`.
#[cfg_attr(any(target_os = "macos", target_os = "windows"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "32"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "macos", target_os = "windows")), target_pointer_width = "64"), repr(u64))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum AttributeClass
{
	#[allow(missing_docs)]
	VendorInformation = SCARD_CLASS_VENDOR_INFO,
	
	#[allow(missing_docs)]
	Communications = SCARD_CLASS_COMMUNICATIONS,
	
	#[allow(missing_docs)]
	Protocol = SCARD_CLASS_PROTOCOL,
	
	#[allow(missing_docs)]
	PowerManagement = SCARD_CLASS_POWER_MGMT,
	
	#[allow(missing_docs)]
	Security = SCARD_CLASS_SECURITY,
	
	#[allow(missing_docs)]
	Mechanical = SCARD_CLASS_MECHANICAL,
	
	#[allow(missing_docs)]
	VendorDefined = SCARD_CLASS_VENDOR_DEFINED,
	
	#[allow(missing_docs)]
	IfdProtocol = SCARD_CLASS_IFD_PROTOCOL,
	
	#[allow(missing_docs)]
	IccState = SCARD_CLASS_ICC_STATE,
	
	#[allow(missing_docs)]
	System = SCARD_CLASS_SYSTEM,
}
