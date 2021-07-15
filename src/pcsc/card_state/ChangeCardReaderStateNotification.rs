// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// How to change card reader state notifications.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum ChangeCardReaderStateNotification
{
	/// Immediately updates with current state.
	Unaware,
	
	/// Ignores state changes.
	Ignore,
	
	/// Sets the currently known state to the last previously known state.
	Update,
}

impl Default for ChangeCardReaderStateNotification
{
	#[inline(always)]
	fn default() -> Self
	{
		ChangeCardReaderStateNotification::Unaware
	}
}
