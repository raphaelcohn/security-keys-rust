// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


pub(in crate::pcsc) const FEATURE_VERIFY_PIN_START: DWORD = 0x01;

pub(in crate::pcsc) const FEATURE_VERIFY_PIN_FINISH: DWORD = 0x02;

pub(in crate::pcsc) const FEATURE_MODIFY_PIN_START: DWORD = 0x03;

pub(in crate::pcsc) const FEATURE_MODIFY_PIN_FINISH: DWORD = 0x04;

pub(in crate::pcsc) const FEATURE_GET_KEY_PRESSED: DWORD = 0x05;

/// Verify PIN.
pub(in crate::pcsc) const FEATURE_VERIFY_PIN_DIRECT: DWORD = 0x06;

/// Modify PIN.
pub(in crate::pcsc) const FEATURE_MODIFY_PIN_DIRECT: DWORD = 0x07;

pub(in crate::pcsc) const FEATURE_MCT_READER_DIRECT: DWORD = 0x08;

pub(in crate::pcsc) const FEATURE_MCT_UNIVERSAL: DWORD = 0x09;

/// Retrieve properties of the IFD regarding PIN handling.
pub(in crate::pcsc) const FEATURE_IFD_PIN_PROPERTIES: DWORD = 0x0A;

pub(in crate::pcsc) const FEATURE_ABORT: DWORD = 0x0B;

pub(in crate::pcsc) const FEATURE_SET_SPE_MESSAGE: DWORD = 0x0C;

pub(in crate::pcsc) const FEATURE_VERIFY_PIN_DIRECT_APP_ID: DWORD = 0x0D;

pub(in crate::pcsc) const FEATURE_MODIFY_PIN_DIRECT_APP_ID: DWORD = 0x0E;

pub(in crate::pcsc) const FEATURE_WRITE_DISPLAY: DWORD = 0x0F;

pub(in crate::pcsc) const FEATURE_GET_KEY: DWORD = 0x10;

pub(in crate::pcsc) const FEATURE_IFD_DISPLAY_PROPERTIES: DWORD = 0x11;

pub(in crate::pcsc) const FEATURE_GET_TLV_PROPERTIES: DWORD = 0x12;

pub(in crate::pcsc) const FEATURE_CCID_ESC_COMMAND: DWORD = 0x13;

pub(in crate::pcsc) const FEATURE_EXECUTE_PACE: DWORD = 0x20;
