// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::c::constants::AttributeClassShift;
use super::c::constants::SCARD_ATTR_ASYNC_PROTOCOL_TYPES;
use super::c::constants::SCARD_ATTR_ATR_STRING;
use super::c::constants::SCARD_ATTR_CHANNEL_ID;
use super::c::constants::SCARD_ATTR_CHARACTERISTICS;
use super::c::constants::SCARD_ATTR_CURRENT_BWT;
use super::c::constants::SCARD_ATTR_CURRENT_CLK;
use super::c::constants::SCARD_ATTR_CURRENT_CWT;
use super::c::constants::SCARD_ATTR_CURRENT_D;
use super::c::constants::SCARD_ATTR_CURRENT_EBC_ENCODING;
use super::c::constants::SCARD_ATTR_CURRENT_F;
use super::c::constants::SCARD_ATTR_CURRENT_IFSC;
use super::c::constants::SCARD_ATTR_CURRENT_IFSD;
use super::c::constants::SCARD_ATTR_CURRENT_IO_STATE;
use super::c::constants::SCARD_ATTR_CURRENT_N;
use super::c::constants::SCARD_ATTR_CURRENT_PROTOCOL_TYPE;
use super::c::constants::SCARD_ATTR_CURRENT_W;
use super::c::constants::SCARD_ATTR_DEFAULT_CLK;
use super::c::constants::SCARD_ATTR_DEFAULT_DATA_RATE;
use super::c::constants::SCARD_ATTR_DEVICE_FRIENDLY_NAME;
use super::c::constants::SCARD_ATTR_DEVICE_IN_USE;
use super::c::constants::SCARD_ATTR_DEVICE_SYSTEM_NAME;
use super::c::constants::SCARD_ATTR_DEVICE_UNIT;
use super::c::constants::SCARD_ATTR_ESC_AUTHREQUEST;
use super::c::constants::SCARD_ATTR_ESC_CANCEL;
use super::c::constants::SCARD_ATTR_ESC_RESET;
use super::c::constants::SCARD_ATTR_EXTENDED_BWT;
use super::c::constants::SCARD_ATTR_ICC_INTERFACE_STATUS;
use super::c::constants::SCARD_ATTR_ICC_PRESENCE;
use super::c::constants::SCARD_ATTR_ICC_TYPE_PER_ATR;
use super::c::constants::SCARD_ATTR_MAXINPUT;
use super::c::constants::SCARD_ATTR_MAX_CLK;
use super::c::constants::SCARD_ATTR_MAX_DATA_RATE;
use super::c::constants::SCARD_ATTR_MAX_IFSD;
use super::c::constants::SCARD_ATTR_POWER_MGMT_SUPPORT;
use super::c::constants::SCARD_ATTR_SUPRESS_T1_IFS_REQUEST;
use super::c::constants::SCARD_ATTR_SYNC_PROTOCOL_TYPES;
use super::c::constants::SCARD_ATTR_USER_AUTH_INPUT_DEVICE;
use super::c::constants::SCARD_ATTR_USER_TO_CARD_AUTH_DEVICE;
use super::c::constants::SCARD_ATTR_VENDOR_IFD_SERIAL_NO;
use super::c::constants::SCARD_ATTR_VENDOR_IFD_TYPE;
use super::c::constants::SCARD_ATTR_VENDOR_IFD_VERSION;
use super::c::constants::SCARD_ATTR_VENDOR_NAME;
use super::c::constants::SCARD_CLASS_COMMUNICATIONS;
use super::c::constants::SCARD_CLASS_ICC_STATE;
use super::c::constants::SCARD_CLASS_IFD_PROTOCOL;
use super::c::constants::SCARD_CLASS_MECHANICAL;
use super::c::constants::SCARD_CLASS_POWER_MGMT;
use super::c::constants::SCARD_CLASS_PROTOCOL;
use super::c::constants::SCARD_CLASS_SECURITY;
use super::c::constants::SCARD_CLASS_SYSTEM;
use super::c::constants::SCARD_CLASS_VENDOR_DEFINED;
use super::c::constants::SCARD_CLASS_VENDOR_INFO;
use super::c::fundamental_types::DWORD;
use std::mem::transmute;


include!("AttributeClass.rs");
include!("AttributeIdentifier.rs");
