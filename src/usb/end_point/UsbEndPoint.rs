// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UsbEndPoint
{
	/// Ignored for control end points.
	direction: UsbDirection,

	transfer_type: UsbTransferType,

	maximum_packet_size: u11,
	
	additional_transaction_opportunities_per_microframe: IsochronousAndInterrruptAdditionalTransactionOpportunitiesPerMicroframe,

	polling_interval: u8,
	
	audio_device_synchronization_feedback_refresh_rate: u8,
	
	audio_device_synchronization_address: u8,

	pub(super) extra: Vec<u8>,
}

impl<'a> From<EndpointDescriptor<'a>> for UsbEndPoint
{
	#[inline(always)]
	fn from(end_point_descriptor: EndpointDescriptor) -> Self
	{
		let max_packet_size = end_point_descriptor.max_packet_size();
		let maximum_packet_size = max_packet_size & 0b0111_1111_1111;
		let additional_transaction_opportunities_per_microframe = unsafe { transmute(((max_packet_size >> 11) & 0b11) as u8) };
		
		Self
		{
			direction: UsbDirection::from(end_point_descriptor.direction()),
		
			transfer_type: UsbTransferType::from(&end_point_descriptor),
			
			maximum_packet_size,
			
			additional_transaction_opportunities_per_microframe,
			
			polling_interval: end_point_descriptor.interval(),
			
			audio_device_synchronization_feedback_refresh_rate: end_point_descriptor.refresh(),
			
			audio_device_synchronization_address: end_point_descriptor.synch_address(),
			
			extra: match end_point_descriptor.extra()
			{
				None => Vec::new(),
				
				Some(bytes) =>
				{
					debug_assert_ne!(bytes.len(), 0);
					bytes.to_vec()
				}
			},
		}
	}
}

impl UsbEndPoint
{
	#[inline(always)]
	pub(super) fn usb_end_points_from(interface_descriptor: InterfaceDescriptor) -> IndexMap<u4, Self>
	{
		let number_of_end_points_excluding_end_point_zero = interface_descriptor.num_endpoints();
		let mut end_points = IndexMap::with_capacity(number_of_end_points_excluding_end_point_zero as usize);
		
		for end_point_descriptor in interface_descriptor.endpoint_descriptors()
		{
			let _ = end_points.insert(end_point_descriptor.number(), Self::from(end_point_descriptor));
		}
		
		end_points
	}
}
