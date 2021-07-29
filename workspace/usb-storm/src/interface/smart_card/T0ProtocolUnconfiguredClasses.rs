// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// The classes `CLA` used in APDU commands before a device is configured when using the ISO 7816 T=0 protocol.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct T0ProtocolUnconfiguredClasses
{
	apdu_get_response: T0ProtocolUnconfiguredClass,

	extended_apdu_envelope: Option<T0ProtocolUnconfiguredClass>,
}

impl T0ProtocolUnconfiguredClasses
{
	/// Indicates the default class value used by the CCID when it sends a Get Response command to perform the transportation of an APDU by T=0 protocol.
	///
	/// This is the value of the `CLA` field.
	#[inline(always)]
	pub const fn apdu_get_response(&self) -> T0ProtocolUnconfiguredClass
	{
		self.apdu_get_response
	}
	
	/// Indicates the default class value used by the CCID when it sends an Envelope command to perform the transportation of an extended APDU by T=0 protocol.
	///
	/// This is the value of the `CLA` field.
	///
	/// `None` if extended APDUs are not supported.
	#[inline(always)]
	pub const fn extended_apdu_envelope(&self) -> Option<T0ProtocolUnconfiguredClass>
	{
		self.extended_apdu_envelope
	}
}
