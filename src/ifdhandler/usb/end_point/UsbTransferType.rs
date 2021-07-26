// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum UsbTransferType
{
	/// Control endpoint.
	Control,
	
	/// Isochronous endpoint.
	Isochronous
	{
		sync_type: UsbIschronousTransferSynchronizationType,
		
		usage_type: UsbIschronousTransferUsageType,
	},
	
	/// Bulk endpoint.
	Bulk,
	
	/// Interrupt endpoint.
	Interrupt,
}

impl<'a> From<&'a EndpointDescriptor<'a>> for UsbTransferType
{
	#[inline(always)]
	fn from(end_point_descriptor: &'a EndpointDescriptor) -> Self
	{
		match end_point_descriptor.transfer_type()
		{
			TransferType::Control => UsbTransferType::Control,
			
			TransferType::Isochronous => UsbTransferType::Isochronous
			{
				sync_type: UsbIschronousTransferSynchronizationType::from(end_point_descriptor.sync_type()),
				
				usage_type: UsbIschronousTransferUsageType::from(end_point_descriptor.usage_type()),
			},
			
			TransferType::Bulk => UsbTransferType::Bulk,
			
			TransferType::Interrupt => UsbTransferType::Interrupt,
		}
	}
}
