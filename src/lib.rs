// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![deny(absolute_paths_not_starting_with_crate)]
#![deny(invalid_html_tags)]
#![deny(macro_use_extern_crate)]
#![deny(missing_crate_level_docs)]
#![deny(missing_docs)]
#![deny(pointer_structural_match)]
#![deny(unaligned_references)]
#![deny(unconditional_recursion)]
#![deny(unreachable_patterns)]
#![deny(unused_import_braces)]
#![deny(unused_must_use)]
#![deny(unused_qualifications)]
#![deny(unused_results)]
#![warn(unreachable_pub)]
#![warn(unused_lifetimes)]
#![warn(unused_crate_dependencies)]


#![feature(allocator_api)]
#![feature(const_fn_transmute)]
#![feature(core_intrinsics)]
#![feature(maybe_uninit_slice)]
#![feature(maybe_uninit_uninit_array)]
#![feature(try_reserve)]


//! security-keys-rust
//! 
//! This is a rust library.


use self::pcsc::CardDisposition;
use self::pcsc::CardSharedAccessBackOff;
use self::pcsc::ConnectedCardOrTransaction;
use self::pcsc::Context;
use self::pcsc::Scope;
use self::pcsc::ShareModeAndPreferredProtocols;
use self::pcsc::attributes::AttributeIdentifier;
use self::pcsc::card_reader_name::CardReaderName;
use self::pcsc::errors::ActivityError;
use arrayvec::ArrayVec;
use std::collections::TryReserveError;


mod pcsc;


mod low_level;


//mod open_pgp;


include!("EXAMPLE.rs");
include!("VecExt.rs");
