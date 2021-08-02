// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Diagnostic device or interface sub class.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum DiagnosticSubClass
{
	/// USB2 Compliance Device.
	///
	/// Definition for this device can be found at <http://www.intel.com/technology/usb/spec.htm>.
	Usb2Compliance
	{
		/// `None` if recognized.
		unrecognized_protocol: Option<u8>,
	},
	
	/// Debug.
	Debug(DebugDiagnosticProtocol),
	
	/// Trace on DbC.
	TraceOnDbC(DiagnosticProtocol),
	
	/// Dfx on DbC.
	DfxOnDbC(DiagnosticProtocol),
	
	/// Trace over General Purpose (GP) end point on DvC.
	TraceOverGeneralPurposeEndPointOnDvC(TraceOverGeneralPurposeEndPointOnDvCDiagnosticProtocol),
	
	#[allow(missing_docs)]
	DfxOnDvC(DiagnosticProtocol),
	
	#[allow(missing_docs)]
	TraceOnDvC(DiagnosticProtocol),
	
	/// Sub class 0x08.
	Miscellaneous
	{
		/// `None` if recognized.
		unrecognized_protocol: Option<NonZeroU8>
	},
	
	/// Unrecognized.
	Unrecognized(UnrecognizedProtocol),
}
