// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[repr(C)]
#[derive(Copy, Clone)]
pub(in crate::ifdhandler) struct ICC_STATE
{
	/// Tag 0x0300.
	pub(in crate::ifdhandler) ICC_Presence: u8,
	
	/// Tag 0x0301.
	pub(in crate::ifdhandler) ICC_Interface_Status: u8,
	
	/// Tag 0x0303.
	pub(in crate::ifdhandler) ATR: [u8; MAX_ATR_SIZE],
	
	/// Tag 0x0304.
	pub(in crate::ifdhandler) ICC_Type: u8,
}

impl Default for ICC_STATE
{
	#[inline(always)]
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

impl Debug for ICC_STATE
{
	#[inline(always)]
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result
	{
		write!(f, "ICC_STATE {{ ICC_Presence: {:?}, ICC_Interface_Status: {:?}, ATR: [{}], ICC_Type: {:?} }}", self.ICC_Presence, self.ICC_Interface_Status, self.ATR.iter().enumerate().map(|(i, v)| format!("{}{:?}", if i > 0 { ", " } else { "" }, v)).collect::<String>(), self.ICC_Type)
	}
}

impl PartialEq for ICC_STATE
{
	#[inline(always)]
	fn eq(&self, other: &Self) -> bool
	{
		self.ICC_Presence == other.ICC_Presence && self.ICC_Interface_Status == other.ICC_Interface_Status && &self.ATR[..] == &other.ATR[..] && self.ICC_Type == other.ICC_Type
	}
}
