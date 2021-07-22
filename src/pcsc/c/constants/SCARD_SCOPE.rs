// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


/// Database operations are performed within the domain of the user.
///
/// Only supported on Windows.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(in crate::pcsc) const SCARD_SCOPE_USER: DWORD = 0x0000;

/// The context is that of the current terminal, and any database operations are performed within the domain of that terminal.
///
/// The calling application must have appropriate access permissions for any database actions.
///
/// See [Interoperability Specification for ICCs and Personal Computer Systems, Part 5 Version 2.01.01, Section 3.1.3](https://pcscworkgroup.com/Download/Specifications/pcsc5_v2.01.01.pdf),
///
/// Partly-supported by Windows (but ignored).
#[allow(dead_code)] const SCARD_SCOPE_TERMINAL: DWORD = 0x0001;

pub(in crate::pcsc) const SCARD_SCOPE_SYSTEM: DWORD = 0x0002;

/// Services are on a remote machine.
///
/// Does nothing in pcsclite or Windows or macos.
#[allow(dead_code)] const SCARD_SCOPE_GLOBAL: DWORD = 0x0003;
