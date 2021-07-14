// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(in crate::pcsc) const SCARD_PROTOCOL_UNDEFINED: DWORD = 0x0000_0000;

pub(in crate::pcsc) const SCARD_PROTOCOL_UNSET: DWORD = SCARD_PROTOCOL_UNDEFINED;

pub(in crate::pcsc) const SCARD_PROTOCOL_T0: DWORD = 0x0000_0001;

pub(in crate::pcsc) const SCARD_PROTOCOL_T1: DWORD = 0x0000_0002;

#[cfg(not(target_os = "windows"))] pub(in crate::pcsc) const SCARD_PROTOCOL_RAW: DWORD = 0x0000_0004;
#[cfg(target_os = "windows")] pub(in crate::pcsc) const SCARD_PROTOCOL_RAW: DWORD = 0x0001_0000;

pub(in crate::pcsc) const SCARD_PROTOCOL_T15: DWORD = 0x0000_0008;

pub(in crate::pcsc) const SCARD_PROTOCOL_ANY: DWORD = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
