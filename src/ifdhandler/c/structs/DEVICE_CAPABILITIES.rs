// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[repr(C)]
#[derive(Debug, Copy, Clone, Hash, PartialOrd, Ord, PartialEq, Eq)]
pub(in crate::ifdhandler) struct DEVICE_CAPABILITIES
{
	/// Tag 0x0100.
	pub(in crate::ifdhandler) Vendor_Name: *mut c_char,
	
	/// Tag 0x0101.
	pub(in crate::ifdhandler) IFD_Type: *mut c_char,
	
	/// Tag 0x0102.
	pub(in crate::ifdhandler) IFD_Version: DWORD,
	
	/// Tag 0x0103.
	pub(in crate::ifdhandler) IFD_Serial: *mut c_char,
	
	/// Tag 0x0110.
	pub(in crate::ifdhandler) IFD_Channel_ID: DWORD,
	
	/// Tag 0x0120.
	pub(in crate::ifdhandler) Asynch_Supported: DWORD,
	
	/// Tag 0x0121.
	pub(in crate::ifdhandler) Default_Clock: DWORD,
	
	/// Tag 0x0122.
	pub(in crate::ifdhandler) Max_Clock: DWORD,
	
	/// Tag 0x0123.
	pub(in crate::ifdhandler) Default_Data_Rate: DWORD,
	
	/// Tag 0x0124.
	pub(in crate::ifdhandler) Max_Data_Rate: DWORD,
	
	/// Tag 0x0125.
	pub(in crate::ifdhandler) Max_IFSD: DWORD,
	
	/// Tag 0x0126.
	pub(in crate::ifdhandler) Synch_Supported: DWORD,
	
	/// Tag 0x0131.
	pub(in crate::ifdhandler) Power_Mgmt: DWORD,
	
	/// Tag 0x0140.
	pub(in crate::ifdhandler) Card_Auth_Devices: DWORD,
	
	/// Tag 0x0142.
	pub(in crate::ifdhandler) User_Auth_Device: DWORD,
	
	/// Tag 0x0150.
	pub(in crate::ifdhandler) Mechanics_Supported: DWORD,
	
	/// Tag 0x0180 - 0x01F0 User Defined..
	pub(in crate::ifdhandler) Vendor_Features: DWORD,
}

impl Default for DEVICE_CAPABILITIES
{
	#[inline(always)]
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}
