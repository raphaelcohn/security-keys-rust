// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Transfer type.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum IschronousTransferUsageType
{
	/// Data.
	Data,
	
	/// Feedback.
	Feedback,
	
	/// Explicit feedback data.
	ImplicitFeedbackData,
}

impl TryFrom<u8> for IschronousTransferUsageType
{
	type Error = TransferTypeParseError;
	
	#[inline(always)]
	fn try_from(bmAttributes: u32) -> Result<Self, Self::Error>
	{
		use self::IschronousTransferUsageType::*;
		
		match (bmAttributes & LIBUSB_ISO_USAGE_TYPE_MASK) >> 4
		{
			LIBUSB_ISO_USAGE_TYPE_DATA => Ok(Data),
			
			LIBUSB_ISO_USAGE_TYPE_FEEDBACK => Ok(Feedback),
			
			LIBUSB_ISO_USAGE_TYPE_IMPLICIT => Ok(ImplicitFeedbackData),
			
			_ => Err(TransferTypeParseError::ReservedUsageType),
		}
	}
}
