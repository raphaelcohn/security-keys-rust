// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct UsbEndPoint
{
	end_point_address: u8,

	end_point_number: u8,

	direction: UsbDirection,

	transfer_type: UsbTransferType,

	maximum_packet_size: u16,

	polling_interval: u8,
	
	audio_device_synchronization_feedback_refresh_rate: u8,
	
	audio_device_synchronization_address: u8,
}

impl<'a> From<EndpointDescriptor<'a>> for UsbEndPoint
{
	#[inline(always)]
	fn from(end_point_descriptor: EndpointDescriptor) -> Self
	{
		Self
		{
			end_point_address: end_point_descriptor.address(),
		
			end_point_number: end_point_descriptor.number(),
		
			direction: UsbDirection::from(end_point_descriptor.direction()),
		
			transfer_type: UsbTransferType::from(&end_point_descriptor),
			
			maximum_packet_size: end_point_descriptor.max_packet_size(),
			
			polling_interval: end_point_descriptor.interval(),
			
			audio_device_synchronization_feedback_refresh_rate: end_point_descriptor.refresh(),
			
			audio_device_synchronization_address: end_point_descriptor.synch_address(),
		}
	}
}

impl UsbEndPoint
{
	#[inline(always)]
	pub(super) fn usb_end_points_from(interface_descriptor: InterfaceDescriptor) -> Vec<Self>
	{
		let number_of_end_points = interface_descriptor.num_endpoints();
		let mut end_points = Vec::with_capacity(number_of_end_points as usize);
		
		for end_point_descriptor in interface_descriptor.endpoint_descriptors()
		{
			end_points.push(Self::from(end_point_descriptor));
		}
		
		end_points
	}
}
