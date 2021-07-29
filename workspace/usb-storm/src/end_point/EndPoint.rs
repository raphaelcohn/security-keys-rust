// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An USB end point.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndPoint
{
	transfer_type: TransferType,

	maximum_packet_size: u11,
	
	audio_device_synchronization_feedback_refresh_rate: u8,
	
	audio_device_synchronization_address: u8,

	additional_descriptors: Vec<AdditionalDescriptor<EndPointAdditionalDescriptor>>,
}

impl EndPoint
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn transfer_type(&self) -> TransferType
	{
		self.transfer_type
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_packet_size(&self) -> u11
	{
		self.maximum_packet_size
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn polling_interval(&self) -> u8
	{
		self.polling_interval
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn audio_device_synchronization_feedback_refresh_rate(&self) -> u8
	{
		self.audio_device_synchronization_feedback_refresh_rate
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn audio_device_synchronization_address(&self) -> u8
	{
		self.audio_device_synchronization_feedback_refresh_rate
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn additional_descriptors(&self) -> &[AdditionalDescriptor<EndPointAdditionalDescriptor>]
	{
		&self.additional_descriptors
	}
	
	#[inline(always)]
	fn try_from(end_point_descriptor: &libusb_endpoint_descriptor, strip_extra: bool) -> Result<Self, EndPointParseError>
	{
		Ok
		(
			Self
			{
				transfer_type: TransferType::try_from(end_point_descriptor)?,
				
				maximum_packet_size: end_point_descriptor.wMaxPacketSize & 0b0111_1111_1111,
				
				audio_device_synchronization_feedback_refresh_rate: end_point_descriptor.refresh(),
				
				audio_device_synchronization_address: end_point_descriptor.synch_address(),
				
				additional_descriptors: Self::parse_additional_descriptors(end_point_descriptor, strip_extra).map_err(UsbError::CouldNotParseEndPointAdditionalDescriptor)?,
			}
		)
	}
	
	#[inline(always)]
	pub(super) fn usb_end_points_from(interface_descriptor: InterfaceDescriptor, strip_last_end_point_of_extra: Option<EndPointNumber>) -> Result<IndexMap<EndPointNumber, Self>, EndPointParseError>
	{
		let number_of_end_points_excluding_end_point_zero = interface_descriptor.num_endpoints();
		let mut end_points = IndexMap::with_capacity(number_of_end_points_excluding_end_point_zero as usize);
		
		for end_point_descriptor in interface_descriptor.endpoint_descriptors()
		{
			let end_point_descriptor = Self::get_libusb_end_point_descriptor(end_point_descriptor);
			
			let bEndpointAddress = end_point_descriptor.bEndpointAddress;
			
			let end_point_number: EndPointNumber = bEndpointAddress & 0x07;
			if unlikely!(end_points.contains_key(&end_point_number))
			{
				return Err(EndPointParseError::DuplicateEndPointNumber(end_point_number))
			}
			
			if (bEndpointAddress & 0b0111_000) != 0
			{
				return Err(EndPointParseError::EndpointAddressHasReservedBits)
			}
			
			let strip_extra = Some(end_point_number) == strip_last_end_point_of_extra;
			let usb_end_point = Self::try_from(end_point_descriptor, strip_extra)?;
			let inserted = end_points.insert(end_point_number, usb_end_point);
			debug_assert!(inserted.is_none());
		}
		
		Ok(end_points)
	}
	
	#[inline(always)]
	fn parse_additional_descriptors(end_point_descriptor: &libusb_endpoint_descriptor, strip_extra: bool) -> Result<Vec<AdditionalDescriptor<EndPointAdditionalDescriptor>>, AdditionalDescriptorParseError<Infallible>>
	{
		let additional_descriptor_parser = EndPointAdditionalDescriptorParser;
		let extra = if strip_extra
		{
			None
		}
		else
		{
			extra_to_slice(end_point_descriptor.extra, end_point_descriptor.extra_length)?
		};
		parse_additional_descriptors(extra, additional_descriptor_parser)
	}
	
	#[inline(always)]
	fn get_libusb_end_point_descriptor(end_point_descriptor: EndpointDescriptor) -> &libusb_endpoint_descriptor
	{
		struct LookAlikeEndpointDescriptor<'a>
		{
			descriptor: &'a libusb_endpoint_descriptor,
		}
		let look_alike_end_point_descriptor: LookAlikeEndpointDescriptor = unsafe { transmute(end_point_descriptor) };
		look_alike_end_point_descriptor.descriptor
	}
}
