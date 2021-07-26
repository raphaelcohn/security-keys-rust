// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


// Windows (ordinal).
#[cfg(target_os = "windows")] pub(in crate::pcsc) const SCARD_UNKNOWN: DWORD = 0;

#[cfg(target_os = "windows")] pub(in crate::pcsc) const SCARD_ABSENT: DWORD = 1;

#[cfg(target_os = "windows")] pub(in crate::pcsc) const SCARD_PRESENT: DWORD = 2;

#[cfg(target_os = "windows")] pub(in crate::pcsc) const SCARD_SWALLOWED: DWORD = 3;

#[cfg(target_os = "windows")] pub(in crate::pcsc) const SCARD_POWERED: DWORD = 4;

#[cfg(target_os = "windows")] pub(in crate::pcsc) const SCARD_NEGOTIABLE: DWORD = 5;

#[cfg(target_os = "windows")] pub(in crate::pcsc) const SCARD_SPECIFIC: DWORD = 6;


// Non-Windows (bitmask).
#[cfg(not(target_os = "windows"))] pub(in crate::pcsc) const SCARD_UNKNOWN: DWORD = 0x0001;

#[cfg(not(target_os = "windows"))] pub(in crate::pcsc) const SCARD_ABSENT: DWORD = 0x0002;

#[cfg(not(target_os = "windows"))] pub(in crate::pcsc) const SCARD_PRESENT: DWORD = 0x0004;

#[cfg(not(target_os = "windows"))] pub(in crate::pcsc) const SCARD_SWALLOWED: DWORD = 0x0008;

#[cfg(not(target_os = "windows"))] pub(in crate::pcsc) const SCARD_POWERED: DWORD = 0x0010;

#[cfg(not(target_os = "windows"))] pub(in crate::pcsc) const SCARD_NEGOTIABLE: DWORD = 0x0020;

#[cfg(not(target_os = "windows"))] pub(in crate::pcsc) const SCARD_SPECIFIC: DWORD = 0x0040;
