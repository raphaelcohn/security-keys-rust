// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct UsbEndPoint
{
	end_point_address: u8,

	end_point_number: u8,

	direction: Direction,

	transfer_type: UsbTransferType,

	maximum_packet_size: u16,

	polling_interval: u8,
	
	audio_device_synchronization_feedback_refresh_reate: u8,
	
	audio_device_synchronization_address: u8,
}

pub(crate) enum UsbTransferType
{
	/// Control endpoint.
	Control,
	
	/// Isochronous endpoint.
	Isochronous
	{
		sync_type: SyncType,
	
		usage_type: UsageType,
	},
	
	/// Bulk endpoint.
	Bulk,
	
	/// Interrupt endpoint.
	Interrupt,
}

impl From for UsbEndPoint
{
	#[inline(always)]
	fn from(end_point_descriptor: EndpointDescriptor) -> Self
	{
		Self
		{
			end_point_address: end_point_descriptor.address(),
		
			end_point_number: end_point_descriptor.number(),
		
			direction: end_point_descriptor.direction(),
		
			transfer_type: match end_point_descriptor.transfer_type()
			{
				TransferType::Control => UsbTransferType::Control,
				
				TransferType::Isochronous => UsbTransferType::Isochronous
				{
					sync_type: end_point_descriptor.sync_type(),
				
					usage_type: end_point_descriptor.usage_type(),
				},
				
				TransferType::Bulk => UsbTransferType::Bulk,
				
				TransferType::Interrupt => UsbTransferType::Interrupt,
			},
			
			maximum_packet_size: end_point_descriptor.max_packet_size(),
			
			polling_interval: end_point_descriptor.interval(),
			
			audio_device_synchronization_feedback_refresh_reate: end_point_descriptor.refresh(),
			
			audio_device_synchronization_address: end_point_descriptor.synch_address(),
		}
	}
}

impl UsbEndPoint
{
	#[inline(always)]
	fn usb_end_points_from(interface_descriptor: InterfaceDescriptor) -> Vec<Self>
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
