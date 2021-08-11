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
	
	audio_extension: Option<EndPointAudioExtension>,

	additional_descriptors: Vec<AdditionalDescriptor<EndPointAdditionalDescriptor>>,
}

impl EndPoint
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn transfer_type(&self) -> &TransferType
	{
		&self.transfer_type
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_packet_size(&self) -> u11
	{
		self.maximum_packet_size
	}
	
	/// Should only be present for Audio devices.
	#[inline(always)]
	pub const fn audio_extension(&self) -> Option<EndPointAudioExtension>
	{
		self.audio_extension
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn additional_descriptors(&self) -> &[AdditionalDescriptor<EndPointAdditionalDescriptor>]
	{
		&self.additional_descriptors
	}
	
	/// Is a periodic end point?
	#[inline(always)]
	pub fn is_a_periodic_end_point(&self) -> bool
	{
		self.transfer_type.is_periodic()
	}
	
	#[inline(always)]
	pub(super) fn parse(end_point_descriptor: &libusb_endpoint_descriptor, maximum_supported_usb_version: Version, string_finder: &StringFinder) -> Result<DeadOrAlive<(EndPointNumber, Self)>, EndPointParseError>
	{
		use EndPointParseError::*;
		
		const LIBUSB_DT_ENDPOINT_SIZE: u8 = 7;
		let bLength = end_point_descriptor.bLength;
		if unlikely!(bLength < LIBUSB_DT_ENDPOINT_SIZE)
		{
			return Err(WrongLength { bLength })
		}
		
		let bDescriptorType = end_point_descriptor.bDescriptorType;
		if unlikely!(bDescriptorType != LIBUSB_DT_ENDPOINT)
		{
			return Err(WrongDescriptorType { bDescriptorType })
		}
		
		let bEndpointAddress = end_point_descriptor.bEndpointAddress;
		if (bEndpointAddress & 0b0111_0000) != 0
		{
			return Err(EndpointAddressHasReservedBits)
		}
		
		const LIBUSB_DT_ENDPOINT_AUDIO_SIZE: u8 = 9;
		
		let audio_extension = if unlikely!(bLength >= LIBUSB_DT_ENDPOINT_AUDIO_SIZE)
		{
			Some
			(
				EndPointAudioExtension
				{
					synchronization_feedback_refresh_rate: end_point_descriptor.bRefresh,
					
					synchronization_address: end_point_descriptor.bSynchAddress,
				}
			)
		}
		else
		{
			None
		};
		
		let mut transfer_type = self::TransferType::parse(end_point_descriptor, maximum_supported_usb_version).map_err(TransferType)?;
		let maximum_packet_size = end_point_descriptor.wMaxPacketSize & 0b0111_1111_1111;
		let additional_descriptors = return_ok_if_dead!(Self::parse_additional_descriptors(string_finder, end_point_descriptor, &mut transfer_type, maximum_packet_size).map_err(CouldNotParseEndPointAdditionalDescriptor)?);
		Ok
		(
			(
				bEndpointAddress & 0b0000_1111,
				
				Self
				{
					transfer_type,
					
					maximum_packet_size,
					
					audio_extension,
					
					additional_descriptors,
				}
			)
		)
	}
	
	#[inline(always)]
	fn parse_additional_descriptors<'a>(string_finder: &StringFinder, end_point_descriptor: &libusb_endpoint_descriptor, transfer_type: &'a mut TransferType, maximum_packet_size: u11) -> Result<DeadOrAlive<Vec<AdditionalDescriptor<EndPointAdditionalDescriptor>>>, AdditionalDescriptorParseError<EndPointAdditionalDescriptorParseError>>
	{
		let extra = extra_to_slice(end_point_descriptor.extra, end_point_descriptor.extra_length)?;
		let additional_descriptor_parser = EndPointAdditionalDescriptorParser
		{
			transfer_type,
			
			maximum_packet_size,
		};
		
		parse_additional_descriptors(string_finder, extra, additional_descriptor_parser)
	}
}
