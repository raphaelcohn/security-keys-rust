// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


//! These C definitions are from the [PCSC project](https://salsa.debian.org/rousseau/PCSC.git).
//!
//! They are contained in the header files:-
//!
//! * `src/PCSC/pcsclite.h.in`
//! * `src/PCSC/winscard.h`
//! * `src/PCSC/winstypes.h`


pub(in crate::pcsc) mod constants;


pub(in crate::pcsc) mod functions;


pub(in crate::pcsc) mod fundamental_types;


pub(in crate::pcsc) mod statics;


pub(in crate::pcsc) mod types;


