// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// `#[repr(DWORD)]`.
#[cfg_attr(any(target_os = "ios", target_os = "macos", target_os = "windows"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "ios", target_os = "macos", target_os = "windows")), target_pointer_width = "32"), repr(u32))]
#[cfg_attr(all(not(any(target_os = "ios", target_os = "macos", target_os = "windows")), target_pointer_width = "64"), repr(u64))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum AttributeClass
{
	/// Vendor information definitions.
	VendorInformation = SCARD_CLASS_VENDOR_INFO,
	
	/// Communication definitions.
	Communication = SCARD_CLASS_COMMUNICATIONS,
	
	/// Protocol definitions.
	Protocol = SCARD_CLASS_PROTOCOL,
	
	/// Power Management definitions.
	PowerManagement = SCARD_CLASS_POWER_MGMT,
	
	/// Security Assurance definitions.
	SecurityAssurance = SCARD_CLASS_SECURITY,
	
	/// Mechanical characteristics definitions.
	MechanicalCharacteristics = SCARD_CLASS_MECHANICAL,
	
	/// Vendor specific definitions.
	VendorSpecific = SCARD_CLASS_VENDOR_DEFINED,
	
	/// Interface Device (IFD) Protocol options.
	InterfaceFeviceProtocol = SCARD_CLASS_IFD_PROTOCOL,
	
	/// ICC State specific definitions.
	IccState = SCARD_CLASS_ICC_STATE,
	
	/// System-specific definitions.
	SystemSpecific = SCARD_CLASS_SYSTEM,
}
