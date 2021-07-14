// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(in crate::pcsc) const SCARD_LEAVE_CARD: DWORD = 0x0000;

pub(in crate::pcsc) const SCARD_RESET_CARD: DWORD = 0x0001;

pub(in crate::pcsc) const SCARD_UNPOWER_CARD: DWORD = 0x0002;

pub(in crate::pcsc) const SCARD_EJECT_CARD: DWORD = 0x0003;
