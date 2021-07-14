// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::constants::ATR_BUFFER_SIZE;
use super::fundamental_types::DWORD;
use super::fundamental_types::LONG;
use libc::c_char;
use libc::c_void;


include!("SCARD_IO_REQUEST.rs");
include!("SCARD_READERSTATE.rs");
include!("SCARDCONTEXT.rs");
include!("SCARDHANDLE.rs");
