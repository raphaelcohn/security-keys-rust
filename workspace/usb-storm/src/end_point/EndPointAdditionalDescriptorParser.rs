// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct EndPointAdditionalDescriptorParser<'a>
{
	transfer_type: &'a mut TransferType,
	
	maximum_packet_size: u11,
}

impl<'a> DescriptorParser for EndPointAdditionalDescriptorParser<'a>
{
	type Descriptor = EndPointAdditionalDescriptor;
	
	type Error = EndPointAdditionalDescriptorParseError;
	
	#[inline(always)]
	fn parse_descriptor(&mut self, _string_finder: &StringFinder, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<DeadOrAlive<(Self::Descriptor, usize)>>, Self::Error>
	{
		use EndPointAdditionalDescriptorParseError::*;
		use TransferType::*;
		
		const LIBUSB_DT_SS_ENDPOINT_COMPANION: u8 = 0x30;
		if descriptor_type != LIBUSB_DT_SS_ENDPOINT_COMPANION
		{
			return Ok(None)
		}
		
		const BLength: u8 = EndPointAdditionalDescriptorParser::BLength;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<EndPointAdditionalDescriptorParseError, BLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		let bMaxBurst = descriptor_body.u8(0);
		let bmAttributes = descriptor_body.u8(1);
		let wBytesInterval = descriptor_body.u16(2);
		
		match bMaxBurst
		{
			 0 ..= 15 => match self.transfer_type
			{
				Control { .. } => if unlikely!(bMaxBurst != 0)
				{
					return Err(ControlEndPointsDoNotSupportPacketBurst)
				},
				
				_ => (),
			},
			
			_ => return Err(InvalidMaximumBurst { bMaxBurst })
		};
		
		let consumed_length = match self.transfer_type
		{
			Control { .. } => descriptor_body_length,
			
			Interrupt { ref mut super_speed, .. } =>
			{
				*super_speed = Some
				(
					SuperSpeedInterrupt
					{
						maximum_number_of_packets_that_can_burst_at_a_time: Self::maximum_number_of_packets_that_can_burst_at_a_time(bMaxBurst),
						
						total_number_of_bytes_transfered_every_service_interval: wBytesInterval,
					}
				);
				descriptor_body_length
			}
			
			Bulk { ref mut super_speed, .. } =>
			{
				*super_speed = Some
				(
					SuperSpeedBulk
					{
						maximum_number_of_packets_that_can_burst_at_a_time: Self::maximum_number_of_packets_that_can_burst_at_a_time(bMaxBurst),
						
						maximum_streams: match bmAttributes & 0b0001_1111
						{
							0 => None,
							
							maximum_streams @ 1 ..= 16 => Some(BulkMaximumStreamsExponent(new_non_zero_u8(maximum_streams))),
							
							maximum_streams @ _ => return Err(InvalidMaximumStreams { maximum_streams }),
						}
					}
				);
				descriptor_body_length
			}
			
			Isochronous { ref mut super_speed, .. } =>
			{
				let bMaxBurst_plus_one = (bMaxBurst + 1) as u32;
				
				// If this field is set to one then a SuperSpeedPlus Isochronous Endpoint Companion descriptor shall immediately follow this descriptor.
				let has_ssp_iso_companion = (bmAttributes & 0b1000_0000) != 0;
				let (additional_consumed_length, super_speed_isochronous) = if has_ssp_iso_companion
				{
					if unlikely!(wBytesInterval != 1)
					{
						return Err(BytesIntervalMustBeOneIfAnIsochronousEndPointHasASuperSpeedPlusIsochronousEndPointCompanionIndicated)
					}
					
					let (dwBytesPerInterval, additional_consumed_length) = Self::parse_super_speed_plus_isochronous_end_point_companion_descriptor(remaining_bytes)?;
					
					(
						additional_consumed_length,
						SuperSpeedIsochronous
						{
							maximum_number_of_packets_that_can_burst_at_a_time: new_non_zero_u32(dwBytesPerInterval / bMaxBurst_plus_one / (self.maximum_packet_size as u32)),
							
							total_number_of_bytes_transfered_every_service_interval: dwBytesPerInterval,
						}
					)
				}
				else
				{
					let mult_plus_1 = match bmAttributes & 0b11
					{
						0 => 1,
						
						mult @  1 ..= 2 => if unlikely!(bMaxBurst == 0)
						{
							return Err(MultIsNotZeroWhenMaximumBurstIsZero { mult })
						}
						else
						{
							(mult + 1) as u32
						},
						
						3 => return Err(MultCanNotBeThree),
						
						_ => unreachable!(),
					};
					
					(
						0,
						SuperSpeedIsochronous
						{
							maximum_number_of_packets_that_can_burst_at_a_time: new_non_zero_u32(mult_plus_1 * bMaxBurst_plus_one),
							
							total_number_of_bytes_transfered_every_service_interval: wBytesInterval as u32,
						}
					)
				};
				
				*super_speed = Some(super_speed_isochronous);
				descriptor_body_length + additional_consumed_length
			}
		};
		
		Ok(Some(Alive((EndPointAdditionalDescriptor::SuperSpeedEndPointCompanion, consumed_length))))
	}
}

impl<'a> EndPointAdditionalDescriptorParser<'a>
{
	const BLength: u8 = 6;
	
	#[inline(always)]
	const fn maximum_number_of_packets_that_can_burst_at_a_time(bMaxBurst: u8) -> NonZeroU4
	{
		new_non_zero_u8(bMaxBurst + 1)
	}
	
	#[inline(always)]
	fn parse_super_speed_plus_isochronous_end_point_companion_descriptor(remaining_bytes: &[u8]) -> Result<(u32, usize), EndPointAdditionalDescriptorParseError>
	{
		use EndPointAdditionalDescriptorParseError::*;
		
		let remaining_bytes = remaining_bytes.get_unchecked_range_safe(reduce_b_length_to_descriptor_body_length(Self::BLength) .. );
		
		if unlikely!(remaining_bytes.len() < DescriptorHeaderLength)
		{
			return Err(ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorMissing)
		}
		
		let bDescriptorType = remaining_bytes.u8(1);
		if unlikely!(bDescriptorType != 49)
		{
			return Err(ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorTypeWrong { bDescriptorType })
		}
		
		let bLength = remaining_bytes.u8(0);
		
		const CompanionBLength: u8 = 10;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<EndPointAdditionalDescriptorParseError, CompanionBLength>(remaining_bytes, bLength, ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorBLengthIsLessThanMinimum, ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorBLengthExceedsRemainingBytes)?;
		debug_assert_eq!(descriptor_body_length, reduce_b_length_to_descriptor_body_length(CompanionBLength));
		let _wReserved = descriptor_body.u16(adjust_descriptor_index::<2>());
		Ok((descriptor_body.u32(adjust_descriptor_index::<4>()), CompanionBLength as usize))
	}
}
