// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


pub(in crate::pcsc) const IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE:DWORD = SCARD_CTL_CODE(1);

pub(in crate::pcsc) const IOCTL_FEATURE_VERIFY_PIN_DIRECT: DWORD = SCARD_CTL_CODE(FEATURE_VERIFY_PIN_DIRECT + CLASS2_IOCTL_MAGIC);

pub(in crate::pcsc) const IOCTL_FEATURE_MODIFY_PIN_DIRECT: DWORD = SCARD_CTL_CODE(FEATURE_MODIFY_PIN_DIRECT + CLASS2_IOCTL_MAGIC);

pub(in crate::pcsc) const IOCTL_FEATURE_MCT_READER_DIRECT: DWORD = SCARD_CTL_CODE(FEATURE_MCT_READER_DIRECT + CLASS2_IOCTL_MAGIC);

pub(in crate::pcsc) const IOCTL_FEATURE_IFD_PIN_PROPERTIES: DWORD = SCARD_CTL_CODE(FEATURE_IFD_PIN_PROPERTIES + CLASS2_IOCTL_MAGIC);

pub(in crate::pcsc) const IOCTL_FEATURE_GET_TLV_PROPERTIES: DWORD = SCARD_CTL_CODE(FEATURE_GET_TLV_PROPERTIES + CLASS2_IOCTL_MAGIC);
