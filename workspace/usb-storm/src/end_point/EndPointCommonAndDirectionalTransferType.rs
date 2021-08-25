// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An USB end point.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndPointCommonAndDirectionalTransferType
{
	#[serde(flatten)]
	common: EndPointCommon,
	
	#[serde(flatten)]
	directional_transfer_type: DirectionalTransferType,
}

impl EndPointCommonAndDirectionalTransferType
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn common(&self) -> &EndPointCommon
	{
		&self.common
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn directional_transfer_type(&self) -> &DirectionalTransferType
	{
		&self.directional_transfer_type
	}
	
	#[inline(always)]
	fn new(common: EndPointCommon, directional_transfer_type: DirectionalTransferType) -> Self
	{
		Self
		{
			common,
			
			directional_transfer_type,
		}
	}
	
}
