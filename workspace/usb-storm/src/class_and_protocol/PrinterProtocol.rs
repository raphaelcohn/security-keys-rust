// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Printer protocol.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum PrinterProtocol
{
	#[allow(missing_docs)]
	ReservedUndefined,
	
	/// Supports the `GET_PORT_STATUS` class-specific command over control end point 0.
	///
	/// Only requires a Bulk Out end point.
	Unidirectional,
	
	/// Supports the `GET_PORT_STATUS` class-specific command over control end point 0.
	///
	/// Requires both a Bulk Out and a Bulk In end point.
	Bidirectional,

	/// Supports IEEE-1284.4 bidirectional interface and transfers using the IEEE P1284.4 Standard for Data delivery and logical channels for IEEE Standard 1284 interfaces, version 1.0.
	///
	/// Requires both a Bulk Out and a Bulk In end point.
	Ieee_1284_4_Bidirectional,
	
	/// Requires both a Bulk Out and a Bulk In end point.
	InternetPrintingProtocolOverUsb,
	
	#[allow(missing_docs)]
	Reserved(u8),
	
	#[allow(missing_docs)]
	VendorSpecific,
}
