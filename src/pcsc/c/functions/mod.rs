// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use libc::c_char;
use libc::c_void;
use super::fundamental_types::DWORD;
use super::fundamental_types::LONG;
use super::types::SCARD_IO_REQUEST;
use super::types::SCARD_READERSTATE;
use super::types::SCARDCONTEXT;
use super::types::SCARDHANDLE;


include!("SCARD_CTL_CODE.rs");
include!("SCardBeginTransaction.rs");
include!("SCardCancel.rs");
include!("SCardConnect.rs");
include!("SCardControl.rs");
include!("SCardDisconnect.rs");
include!("SCardEndTransaction.rs");
include!("SCardEstablishContext.rs");
include!("SCardFreeMemory.rs");
include!("SCardGetAttrib.rs");
include!("SCardGetStatusChange.rs");
include!("SCardIsValidContext.rs");
include!("SCardListReaderGroups.rs");
include!("SCardListReaders.rs");
include!("SCardReconnect.rs");
include!("SCardReleaseContext.rs");
include!("SCardSetAttrib.rs");
include!("SCardStatus.rs");
include!("SCardTransmit.rs");
