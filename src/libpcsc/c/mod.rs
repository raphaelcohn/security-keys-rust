// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use self::constants::AttributeClassShift;
use self::constants::INFINITE;
use self::constants::PCSCLITE_MAX_READERS_CONTEXTS;
use self::constants::SCARD_ATTR_ASYNC_PROTOCOL_TYPES;
use self::constants::SCARD_ATTR_ATR_STRING;
use self::constants::SCARD_ATTR_CHANNEL_ID;
use self::constants::SCARD_ATTR_CHARACTERISTICS;
use self::constants::SCARD_ATTR_CURRENT_BWT;
use self::constants::SCARD_ATTR_CURRENT_CLK;
use self::constants::SCARD_ATTR_CURRENT_CWT;
use self::constants::SCARD_ATTR_CURRENT_D;
use self::constants::SCARD_ATTR_CURRENT_EBC_ENCODING;
use self::constants::SCARD_ATTR_CURRENT_F;
use self::constants::SCARD_ATTR_CURRENT_IFSC;
use self::constants::SCARD_ATTR_CURRENT_IFSD;
use self::constants::SCARD_ATTR_CURRENT_IO_STATE;
use self::constants::SCARD_ATTR_CURRENT_N;
use self::constants::SCARD_ATTR_CURRENT_PROTOCOL_TYPE;
use self::constants::SCARD_ATTR_CURRENT_W;
use self::constants::SCARD_ATTR_DEFAULT_CLK;
use self::constants::SCARD_ATTR_DEFAULT_DATA_RATE;
use self::constants::SCARD_ATTR_DEVICE_FRIENDLY_NAME;
use self::constants::SCARD_ATTR_DEVICE_IN_USE;
use self::constants::SCARD_ATTR_DEVICE_SYSTEM_NAME;
use self::constants::SCARD_ATTR_DEVICE_UNIT;
use self::constants::SCARD_ATTR_ESC_AUTHREQUEST;
use self::constants::SCARD_ATTR_ESC_CANCEL;
use self::constants::SCARD_ATTR_ESC_RESET;
use self::constants::SCARD_ATTR_EXTENDED_BWT;
use self::constants::SCARD_ATTR_ICC_INTERFACE_STATUS;
use self::constants::SCARD_ATTR_ICC_PRESENCE;
use self::constants::SCARD_ATTR_ICC_TYPE_PER_ATR;
use self::constants::SCARD_ATTR_MAXINPUT;
use self::constants::SCARD_ATTR_MAX_CLK;
use self::constants::SCARD_ATTR_MAX_DATA_RATE;
use self::constants::SCARD_ATTR_MAX_IFSD;
use self::constants::SCARD_ATTR_POWER_MGMT_SUPPORT;
use self::constants::SCARD_ATTR_SUPRESS_T1_IFS_REQUEST;
use self::constants::SCARD_ATTR_SYNC_PROTOCOL_TYPES;
use self::constants::SCARD_ATTR_USER_AUTH_INPUT_DEVICE;
use self::constants::SCARD_ATTR_USER_TO_CARD_AUTH_DEVICE;
use self::constants::SCARD_ATTR_VENDOR_IFD_SERIAL_NO;
use self::constants::SCARD_ATTR_VENDOR_IFD_TYPE;
use self::constants::SCARD_ATTR_VENDOR_IFD_VERSION;
use self::constants::SCARD_ATTR_VENDOR_NAME;
use self::constants::SCARD_CLASS_COMMUNICATIONS;
use self::constants::SCARD_CLASS_ICC_STATE;
use self::constants::SCARD_CLASS_IFD_PROTOCOL;
use self::constants::SCARD_CLASS_MECHANICAL;
use self::constants::SCARD_CLASS_POWER_MGMT;
use self::constants::SCARD_CLASS_PROTOCOL;
use self::constants::SCARD_CLASS_SECURITY;
use self::constants::SCARD_CLASS_SYSTEM;
use self::constants::SCARD_CLASS_VENDOR_DEFINED;
use self::constants::SCARD_CLASS_VENDOR_INFO;
use self::constants::SCARD_E_INSUFFICIENT_BUFFER;
use self::constants::SCARD_E_INVALID_HANDLE;
use self::constants::SCARD_E_INVALID_PARAMETER;
use self::constants::SCARD_E_INVALID_VALUE;
use self::constants::SCARD_E_NO_MEMORY;
use self::constants::SCARD_E_NO_READERS_AVAILABLE;
use self::constants::SCARD_E_NO_SERVICE;
use self::constants::SCARD_F_COMM_ERROR;
use self::constants::SCARD_F_INTERNAL_ERROR;
use self::constants::SCARD_EJECT_CARD;
use self::constants::SCARD_LEAVE_CARD;
use self::constants::SCARD_PROTOCOL_RAW;
use self::constants::SCARD_PROTOCOL_T0;
use self::constants::SCARD_PROTOCOL_T1;
use self::constants::SCARD_PROTOCOL_T15;
use self::constants::SCARD_RESET_CARD;
use self::constants::SCARD_S_SUCCESS;
use self::constants::SCARD_SCOPE_GLOBAL;
use self::constants::SCARD_SCOPE_SYSTEM;
use self::constants::SCARD_SCOPE_TERMINAL;
use self::constants::SCARD_SCOPE_USER;
use self::constants::SCARD_SHARE_DIRECT;
use self::constants::SCARD_SHARE_EXCLUSIVE;
use self::constants::SCARD_SHARE_SHARED;
use self::constants::SCARD_UNPOWER_CARD;
use self::functions::SCARD_CTL_CODE;
use self::functions::SCardCancel;
use self::functions::SCardGetStatusChange;
use self::functions::SCardEstablishContext;
use self::functions::SCardListReaders;
use self::functions::SCardIsValidContext;
use self::functions::SCardReleaseContext;
use self::fundamental_types::DWORD;
use self::statics::g_rgSCardRawPci;
use self::statics::g_rgSCardT0Pci;
use self::statics::g_rgSCardT1Pci;
use self::types::SCARD_IO_REQUEST;
use self::types::SCARD_READERSTATE;
use self::types::SCARDCONTEXT;
use arrayvec::ArrayVec;
use enumflags2::BitFlags;
use enumflags2::bitflags;
use libc::c_char;
use likely::likely;
use likely::unlikely;
use memchr::memchr;
use std::collections::HashSet;
use std::error;
use std::ffi::CStr;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::mem::needs_drop;
use std::mem::transmute;
use std::num::NonZeroU32;
use std::ptr::drop_in_place;
use std::ptr::null;
use std::ptr::null_mut;
use std::rc::Rc;
use swiss_army_knife::get_unchecked::GetUnchecked;


pub(in crate::libpcsc) mod constants;


pub(in crate::libpcsc) mod functions;


pub(in crate::libpcsc) mod fundamental_types;


pub(in crate::libpcsc) mod statics;


pub(in crate::libpcsc) mod types;


include!("Attribute.rs");
include!("AttributeClass.rs");
include!("BufferProvider.rs");
include!("Context.rs");
include!("ContextEstablishmentError.rs");
include!("ContextInner.rs");
include!("ControlCode.rs");
include!("CardDisposition.rs");
include!("Protocol.rs");
include!("ReaderNames.rs");
include!("Scope.rs");
include!("ShareMode.rs");
include!("Timeout.rs");


#[repr(transparent)]
struct ReaderState(SCARD_READERSTATE);
