// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// DVD Common Interface (DVB-CI).
///
/// The DVB Common Interface (DVB-CI) specification describes a system whereby a removable CI Conditional Access Module (CICAM), given the appropriate usage rights, unscrambles protected pay-TV content and routes it over the same interface back to a TV receiver for display.
/// An interface association for a DVB-CI function will contain a DVB-CI Command Interface for command, control, and status information, it may contain a DVB-CI Media Interface for audiovisual data streams, and it may also contain a CDC EEM interface to provide bridged networking to the CICAM.
///
/// See <https://www.dvb.org/standards/dvb-ci-plus>.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum DvbCommonDeviceProtocol
{
	#[allow(missing_docs)]
	CommandInterface,
	
	#[allow(missing_docs)]
	UnrecognizedProtocol(u8),
}
