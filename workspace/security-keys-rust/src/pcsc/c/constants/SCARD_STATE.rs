// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


pub(in crate::pcsc) const SCARD_STATE_UNAWARE: DWORD = 0x0000;

pub(in crate::pcsc) const SCARD_STATE_IGNORE: DWORD = 0x0001;

pub(in crate::pcsc) const SCARD_STATE_CHANGED: DWORD = 0x0002;

pub(in crate::pcsc) const SCARD_STATE_UNKNOWN: DWORD = 0x0004;

pub(in crate::pcsc) const SCARD_STATE_UNAVAILABLE: DWORD = 0x0008;

pub(in crate::pcsc) const SCARD_STATE_EMPTY: DWORD = 0x0010;

pub(in crate::pcsc) const SCARD_STATE_PRESENT: DWORD = 0x0020;

#[allow(dead_code)]
const SCARD_STATE_ATRMATCH: DWORD = 0x0040;

pub(in crate::pcsc) const SCARD_STATE_EXCLUSIVE: DWORD = 0x0080;

pub(in crate::pcsc) const SCARD_STATE_INUSE: DWORD = 0x0100;

pub(in crate::pcsc) const SCARD_STATE_MUTE: DWORD = 0x0200;

#[allow(dead_code)]
const SCARD_STATE_UNPOWERED: DWORD = 0x0400;
