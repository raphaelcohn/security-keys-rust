// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


pub(in crate::libpcsc) const SCARD_E_BAD_SEEK: LONG = 0x8010_0029u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_CANCELLED: LONG = 0x8010_0002u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_CANT_DISPOSE: LONG = 0x8010_000Eu32 as LONG;

pub(in crate::libpcsc) const SCARD_E_CARD_UNSUPPORTED: LONG = 0x8010_001Cu32 as LONG;

pub(in crate::libpcsc) const SCARD_E_CERTIFICATE_UNAVAILABLE: LONG = 0x8010_002Du32 as LONG;

pub(in crate::libpcsc) const SCARD_E_COMM_DATA_LOST: LONG = 0x8010_002Fu32 as LONG;

pub(in crate::libpcsc) const SCARD_E_DIR_NOT_FOUND: LONG = 0x8010_0023u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_DUPLICATE_READER: LONG = 0x8010_001Bu32 as LONG;

pub(in crate::libpcsc) const SCARD_E_FILE_NOT_FOUND: LONG = 0x8010_0024u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_ICC_CREATEORDER: LONG = 0x8010_0021u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_ICC_INSTALLATION: LONG = 0x8010_0020u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_INSUFFICIENT_BUFFER: LONG = 0x8010_0008u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_INVALID_ATR: LONG = 0x8010_0015u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_INVALID_CHV: LONG = 0x8010_002Au32 as LONG;

pub(in crate::libpcsc) const SCARD_E_INVALID_HANDLE: LONG = 0x8010_0003u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_INVALID_PARAMETER: LONG = 0x8010_0004u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_INVALID_TARGET: LONG = 0x8010_0005u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_INVALID_VALUE: LONG = 0x8010_0011u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_NOT_READY: LONG = 0x8010_0010u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_NOT_TRANSACTED: LONG = 0x8010_0016u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_NO_ACCESS: LONG = 0x8010_0027u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_NO_DIR: LONG = 0x8010_0025u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_NO_FILE: LONG = 0x8010_0026u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_NO_KEY_CONTAINER: LONG = 0x8010_0030u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_NO_MEMORY: LONG = 0x8010_0006u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_NO_READERS_AVAILABLE: LONG = 0x8010_002Eu32 as LONG;

pub(in crate::libpcsc) const SCARD_E_NO_SERVICE: LONG = 0x8010_001Du32 as LONG;

pub(in crate::libpcsc) const SCARD_E_NO_SMARTCARD: LONG = 0x8010_000Cu32 as LONG;

pub(in crate::libpcsc) const SCARD_E_NO_SUCH_CERTIFICATE: LONG = 0x8010_002Cu32 as LONG;

pub(in crate::libpcsc) const SCARD_E_PCI_TOO_SMALL: LONG = 0x8010_0019u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_PROTO_MISMATCH: LONG = 0x8010_000Fu32 as LONG;

pub(in crate::libpcsc) const SCARD_E_READER_UNAVAILABLE: LONG = 0x8010_0017u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_READER_UNSUPPORTED: LONG = 0x8010_001Au32 as LONG;

pub(in crate::libpcsc) const SCARD_E_SERVER_TOO_BUSY: LONG = 0x8010_0031u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_SERVICE_STOPPED: LONG = 0x8010_001Eu32 as LONG;

pub(in crate::libpcsc) const SCARD_E_SHARING_VIOLATION: LONG = 0x8010_000Bu32 as LONG;

pub(in crate::libpcsc) const SCARD_E_SYSTEM_CANCELLED: LONG = 0x8010_0012u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_TIMEOUT: LONG = 0x8010_000Au32 as LONG;

pub(in crate::libpcsc) const SCARD_E_UNEXPECTED: LONG = 0x8010_001Fu32 as LONG;

pub(in crate::libpcsc) const SCARD_E_UNKNOWN_CARD: LONG = 0x8010_000Du32 as LONG;

pub(in crate::libpcsc) const SCARD_E_UNKNOWN_READER: LONG = 0x8010_0009u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_UNKNOWN_RES_MNG: LONG = 0x8010_002Bu32 as LONG;

#[cfg(not(target_os = "windows"))] pub(in crate::libpcsc) const SCARD_E_UNSUPPORTED_FEATURE: LONG = 0x8010_001Fu32 as LONG;
#[cfg(target_os = "windows")] pub(in crate::libpcsc) const SCARD_E_UNSUPPORTED_FEATURE: LONG = 0x8010_0022u32 as LONG;

pub(in crate::libpcsc) const SCARD_E_WRITE_TOO_MANY: LONG = 0x8010_0028u32 as LONG;
