// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use likely::likely;
use likely::unlikely;
use libusb1_sys::libusb_context;
use libusb1_sys::libusb_exit;
use libusb1_sys::libusb_init;
use libusb1_sys::constants::LIBUSB_ERROR_ACCESS;
use libusb1_sys::constants::LIBUSB_ERROR_BUSY;
use libusb1_sys::constants::LIBUSB_ERROR_INTERRUPTED;
use libusb1_sys::constants::LIBUSB_ERROR_INVALID_PARAM;
use libusb1_sys::constants::LIBUSB_ERROR_IO;
use libusb1_sys::constants::LIBUSB_ERROR_NOT_FOUND;
use libusb1_sys::constants::LIBUSB_ERROR_NOT_SUPPORTED;
use libusb1_sys::constants::LIBUSB_ERROR_NO_DEVICE;
use libusb1_sys::constants::LIBUSB_ERROR_NO_MEM;
use libusb1_sys::constants::LIBUSB_ERROR_OTHER;
use libusb1_sys::constants::LIBUSB_ERROR_OVERFLOW;
use libusb1_sys::constants::LIBUSB_ERROR_PIPE;
use libusb1_sys::constants::LIBUSB_ERROR_TIMEOUT;
use std::alloc::Allocator;
use std::alloc::AllocError;
use std::alloc::Global;
use std::alloc::Layout;
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::lazy::SyncOnceCell;
use std::num::NonZeroUsize;
use std::ptr::NonNull;
use std::ptr::null_mut;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::SeqCst;
use swiss_army_knife::non_zero::new_non_zero_usize;
use std::mem::MaybeUninit;


include!("Context.rs");
include!("ContextInitializationError.rs");
include!("ContextInner.rs");
