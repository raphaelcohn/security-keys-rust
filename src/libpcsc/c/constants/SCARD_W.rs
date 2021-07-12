// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(in crate::libpcsc) const SCARD_W_CACHE_ITEM_NOT_FOUND: LONG = 0x8010_0070;

pub(in crate::libpcsc) const SCARD_W_CACHE_ITEM_STALE: LONG = 0x8010_0071;

pub(in crate::libpcsc) const SCARD_W_CACHE_ITEM_TOO_BIG: LONG = 0x8010_0072;

pub(in crate::libpcsc) const SCARD_W_CANCELLED_BY_USER: LONG = 0x8010_006E;

pub(in crate::libpcsc) const SCARD_W_CARD_NOT_AUTHENTICATED: LONG = 0x8010_006F;

pub(in crate::libpcsc) const SCARD_W_CHV_BLOCKED: LONG = 0x8010_006C;

pub(in crate::libpcsc) const SCARD_W_EOF: LONG = 0x8010_006D;

pub(in crate::libpcsc) const SCARD_W_REMOVED_CARD: LONG = 0x8010_0069;

pub(in crate::libpcsc) const SCARD_W_RESET_CARD: LONG = 0x8010_0068;

pub(in crate::libpcsc) const SCARD_W_SECURITY_VIOLATION: LONG = 0x8010_006A;

pub(in crate::libpcsc) const SCARD_W_UNPOWERED_CARD: LONG = 0x8010_0067;

pub(in crate::libpcsc) const SCARD_W_UNRESPONSIVE_CARD: LONG = 0x8010_0066;

pub(in crate::libpcsc) const SCARD_W_UNSUPPORTED_CARD: LONG = 0x8010_0065;

pub(in crate::libpcsc) const SCARD_W_WRONG_CHV: LONG = 0x8010_006B;
