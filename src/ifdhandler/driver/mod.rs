// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


use self::ifd_ccid::fixed_driver_capabilities_ifd_ccid;
use self::ifd_ccid::our_driver_name_ifd_ccid;
use self::ifd_ccid::validate_info_plist_ifd_ccid;
use super::LogicalUnitNumber;
use super::c::constants::response_codes::IFD_COMMUNICATION_ERROR;
use super::c::constants::response_codes::IFD_ICC_NOT_PRESENT;
use super::c::constants::response_codes::IFD_ICC_PRESENT;
use super::c::constants::response_codes::IFD_NO_SUCH_DEVICE;
use super::c::constants::response_codes::IFD_SUCCESS;
use super::c::structs::SCARD_IO_HEADER;
use super::c::types::DWORD;
use super::c::types::RESPONSECODE;
use super::errors::CreateChannelUnexpectedError;
use super::errors::GenericError;
use super::errors::PresenceUnexpectedError;
use crate::usb::FixedUsbDeviceCapabilities;
use crate::usb::UsbDeviceInformationDatabase;
use crate::usb::UsbProductIdentifier;
use crate::usb::UsbVendorIdentifier;
use crate::VecExt;
use enumflags2::BitFlags;
use enumflags2::bitflags;
use enumflags2::FromBitsError;
use errno::errno;
use libc::c_char;
use libc::EFAULT;
use libc::uname;
use libc::utsname;
use libloading::Library;
use likely::likely;
use likely::unlikely;
use plist::Dictionary;
use plist::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::TryReserveError;
use std::error;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt;
use std::fs::DirEntry;
use std::lazy::SyncLazy;
use std::mem::forget;
use std::mem::size_of;
use std::mem::transmute;
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use swiss_army_knife::path::PathBufExt;
use swiss_army_knife::strings::parse_number::ParseNumber;
use swiss_army_knife::strings::parse_number::ParseNumberError;
use swiss_army_knife::get_unchecked::GetUnchecked;
use std::num::NonZeroUsize;
use swiss_army_knife::non_zero::new_non_zero_usize;


mod ifd_ccid;


include!("Driver.rs");
include!("DriverCapabilities.rs");
include!("DriverDetails.rs");
include!("DriverFunctions.rs");
include!("DriverInfoPListValidater.rs");
include!("DriverInformationDatabase.rs");
include!("DriverLocation.rs");
include!("DriverUsbDeviceName.rs");
include!("FixedDriverCapabilities.rs");
include!("dictionary_get_string.rs");
include!("KnownSymbolName.rs");
include!("LoadDriverError.rs");
include!("OurDriverName.rs");
include!("RawSymbol.rs");
