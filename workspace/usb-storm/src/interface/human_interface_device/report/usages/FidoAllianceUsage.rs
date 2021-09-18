// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// FIDO Alliance usage.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum FidoAllianceUsage
{
	#[allow(missing_docs)]
	Undefined,
	
	#[allow(missing_docs)]
	U2FAuthenticatorDevice,
	
	#[allow(missing_docs)]
	InputReportData,
	
	#[allow(missing_docs)]
	OutputReportData,
	
	#[allow(missing_docs)]
	Reserved(u16),
}

impl Default for FidoAllianceUsage
{
	#[inline(always)]
	fn default() -> Self
	{
		FidoAllianceUsage::Undefined
	}
}

impl From<UsageIdentifier> for FidoAllianceUsage
{
	#[inline(always)]
	fn from(identifier: UsageIdentifier) -> Self
	{
		use FidoAllianceUsage::*;
		
		match identifier
		{
			0x00 => Undefined,
			
			0x01 => U2FAuthenticatorDevice,
			
			value @ 0x02 ..= 0x1F => Reserved(value),
			
			0x20 => InputReportData,
			
			0x21 => OutputReportData,
			
			value @ 0x22 ..= 0xFFFF => Reserved(value),
		}
	}
}
