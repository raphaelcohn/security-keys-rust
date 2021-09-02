// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An USB end point.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndPointCommon
{
	maximum_packet_size: u11,
	
	audio_extension: Option<EndPointAudioExtension>,

	descriptors: Vec<EndPointExtraDescriptor>,
}

impl EndPointCommon
{
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
	pub fn descriptors(&self) -> &[EndPointExtraDescriptor]
	{
		&self.descriptors
	}
	
	#[inline(always)]
	pub(super) fn parse(end_point_descriptor: &libusb_endpoint_descriptor, interface_class: InterfaceClass, string_finder: &StringFinder, bLength: u8, transfer_type: &mut Either<Option<NonZeroU8>, (Direction, DirectionalTransferType)>) -> Result<DeadOrAlive<Self>, EndPointParseError>
	{
		use EndPointParseError::*;
		
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
		
		let maximum_packet_size = end_point_descriptor.wMaxPacketSize & 0b0111_1111_1111;
		let descriptors = Self::parse_descriptors(string_finder, end_point_descriptor, interface_class, transfer_type, maximum_packet_size).map_err(CouldNotParseEndPointAdditionalDescriptor)?;
		let descriptors = return_ok_if_dead!(descriptors);
		Ok
		(
			Alive
			(
				Self
				{
					maximum_packet_size,
					
					audio_extension,
					
					descriptors,
				}
			)
		)
	}
	
	#[inline(always)]
	fn parse_descriptors<'a>(string_finder: &StringFinder, end_point_descriptor: &libusb_endpoint_descriptor, interface_class: InterfaceClass, transfer_type: &'a mut Either<Option<NonZeroU8>, (Direction, DirectionalTransferType)>, maximum_packet_size: u11) -> Result<DeadOrAlive<Vec<EndPointExtraDescriptor>>, DescriptorParseError<EndPointExtraDescriptorParseError>>
	{
		let extra = extra_to_slice(end_point_descriptor.extra, end_point_descriptor.extra_length)?;
		let descriptor_parser = EndPointExtraDescriptorParser
		{
			super_speed_end_point_companion_descriptor_parser: SuperSpeedEndPointCompanionDescriptorParser
			{
				transfer_type,
				
				maximum_packet_size,
			},
			
			interface_class,
		};
		
		parse_descriptors(string_finder, extra, descriptor_parser)
	}
}
