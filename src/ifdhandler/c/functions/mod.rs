// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use super::types::DWORD;
use super::types::RESPONSECODE;
use libc::c_char;


include!("IFDHCloseChannel.rs");
include!("IFDHControl.rs");
include!("IFDHCreateChannel.rs");
include!("IFDHCreateChannelByName.rs");
include!("IFDHGetCapabilities.rs");
include!("IFDHICCPresence.rs");
include!("IFDHPowerICC.rs");
include!("IFDHSetCapabilities.rs");
include!("IFDHSetProtocolParameters.rs");
include!("IFDHTransmitToICC.rs");
