// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// In, out or both directions.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum DirectionalEndPoint
{
	#[allow(missing_docs)]
	In
	{
		#[serde(rename = "in")]
		#[serde(flatten)]
		in_: EndPointCommonAndDirectionalTransferType,
	},
	
	#[allow(missing_docs)]
	Out
	{
		#[serde(flatten)]
		out: EndPointCommonAndDirectionalTransferType,
	},
	
	#[allow(missing_docs)]
	InAndOut
	{
		#[serde(rename = "in")]
		in_: EndPointCommonAndDirectionalTransferType,
		
		out: EndPointCommonAndDirectionalTransferType,
	},
}
