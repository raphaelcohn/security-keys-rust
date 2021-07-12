// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(in crate::libpcsc) const SCARD_E_BAD_SEEK: LONG = 0x8010_0029;
pub(in crate::libpcsc) const SCARD_E_CANCELLED: LONG = 0x8010_0002;
pub(in crate::libpcsc) const SCARD_E_CANT_DISPOSE: LONG = 0x8010_000E;
pub(in crate::libpcsc) const SCARD_E_CARD_UNSUPPORTED: LONG = 0x8010_001C;
pub(in crate::libpcsc) const SCARD_E_CERTIFICATE_UNAVAILABLE: LONG = 0x8010_002D;
pub(in crate::libpcsc) const SCARD_E_COMM_DATA_LOST: LONG = 0x8010_002F;
pub(in crate::libpcsc) const SCARD_E_DIR_NOT_FOUND: LONG = 0x8010_0023;
pub(in crate::libpcsc) const SCARD_E_DUPLICATE_READER: LONG = 0x8010_001B;
pub(in crate::libpcsc) const SCARD_E_FILE_NOT_FOUND: LONG = 0x8010_0024;
pub(in crate::libpcsc) const SCARD_E_ICC_CREATEORDER: LONG = 0x8010_0021;
pub(in crate::libpcsc) const SCARD_E_ICC_INSTALLATION: LONG = 0x8010_0020;
pub(in crate::libpcsc) const SCARD_E_INSUFFICIENT_BUFFER: LONG = 0x8010_0008;
pub(in crate::libpcsc) const SCARD_E_INVALID_ATR: LONG = 0x8010_0015;
pub(in crate::libpcsc) const SCARD_E_INVALID_CHV: LONG = 0x8010_002A;
pub(in crate::libpcsc) const SCARD_E_INVALID_HANDLE: LONG = 0x8010_0003;
pub(in crate::libpcsc) const SCARD_E_INVALID_PARAMETER: LONG = 0x8010_0004;
pub(in crate::libpcsc) const SCARD_E_INVALID_TARGET: LONG = 0x8010_0005;
pub(in crate::libpcsc) const SCARD_E_INVALID_VALUE: LONG = 0x8010_0011;
pub(in crate::libpcsc) const SCARD_E_NOT_READY: LONG = 0x8010_0010;
pub(in crate::libpcsc) const SCARD_E_NOT_TRANSACTED: LONG = 0x8010_0016;
pub(in crate::libpcsc) const SCARD_E_NO_ACCESS: LONG = 0x8010_0027;
pub(in crate::libpcsc) const SCARD_E_NO_DIR: LONG = 0x8010_0025;
pub(in crate::libpcsc) const SCARD_E_NO_FILE: LONG = 0x8010_0026;
pub(in crate::libpcsc) const SCARD_E_NO_KEY_CONTAINER: LONG = 0x8010_0030;
pub(in crate::libpcsc) const SCARD_E_NO_MEMORY: LONG = 0x8010_0006;
pub(in crate::libpcsc) const SCARD_E_NO_READERS_AVAILABLE: LONG = 0x8010_002E;
pub(in crate::libpcsc) const SCARD_E_NO_SERVICE: LONG = 0x8010_001D;
pub(in crate::libpcsc) const SCARD_E_NO_SMARTCARD: LONG = 0x8010_000C;
pub(in crate::libpcsc) const SCARD_E_NO_SUCH_CERTIFICATE: LONG = 0x8010_002C;
pub(in crate::libpcsc) const SCARD_E_PCI_TOO_SMALL: LONG = 0x8010_0019;
pub(in crate::libpcsc) const SCARD_E_PROTO_MISMATCH: LONG = 0x8010_000F;
pub(in crate::libpcsc) const SCARD_E_READER_UNAVAILABLE: LONG = 0x8010_0017;
pub(in crate::libpcsc) const SCARD_E_READER_UNSUPPORTED: LONG = 0x8010_001A;
pub(in crate::libpcsc) const SCARD_E_SERVER_TOO_BUSY: LONG = 0x8010_0031;
pub(in crate::libpcsc) const SCARD_E_SERVICE_STOPPED: LONG = 0x8010_001E;
pub(in crate::libpcsc) const SCARD_E_SHARING_VIOLATION: LONG = 0x8010_000B;
pub(in crate::libpcsc) const SCARD_E_SYSTEM_CANCELLED: LONG = 0x8010_0012;
pub(in crate::libpcsc) const SCARD_E_TIMEOUT: LONG = 0x8010_000A;
pub(in crate::libpcsc) const SCARD_E_UNEXPECTED: LONG = 0x8010_001F;
pub(in crate::libpcsc) const SCARD_E_UNKNOWN_CARD: LONG = 0x8010_000D;
pub(in crate::libpcsc) const SCARD_E_UNKNOWN_READER: LONG = 0x8010_0009;
pub(in crate::libpcsc) const SCARD_E_UNKNOWN_RES_MNG: LONG = 0x8010_002B;
#[cfg(not(target_os = "windows"))] pub(in crate::libpcsc) const SCARD_E_UNSUPPORTED_FEATURE: LONG = 0x8010_001F;
#[cfg(target_os = "windows")] pub(in crate::libpcsc) const SCARD_E_UNSUPPORTED_FEATURE: LONG = 0x8010_0022;
pub(in crate::libpcsc) const SCARD_E_WRITE_TOO_MANY: LONG = 0x8010_0028;
