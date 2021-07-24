// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum UsbIschronousTransferUsageType
{
	/// Data endpoint.
	Data,
	
	/// Feedback endpoint.
	Feedback,
	
	/// Explicit feedback data endpoint.
	FeedbackData,
	
	/// Reserved.
	Reserved,
}

impl From<UsageType> for UsbIschronousTransferUsageType
{
	#[inline(always)]
	fn from(usage_type: UsageType) -> Self
	{
		match usage_type
		{
			UsageType::Data => UsbIschronousTransferUsageType::Data,
			
			UsageType::Feedback => UsbIschronousTransferUsageType::Feedback,
			
			UsageType::FeedbackData => UsbIschronousTransferUsageType::FeedbackData,
			
			UsageType::Reserved => UsbIschronousTransferUsageType::Reserved,
		}
	}
}
