// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct EndPointAdditionalDescriptorParser<'a>
{
	transfer_type: &'a mut TransferType,
	
	maximum_packet_size: u11,
}

impl<'a> AdditionalDescriptorParser for EndPointAdditionalDescriptorParser<'a>
{
	type Descriptor = EndPointAdditionalDescriptor;
	
	type Error = EndPointAdditionalDescriptorParseError;
	
	#[inline(always)]
	fn parse_descriptor(&mut self, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<(Self::Descriptor, usize)>, Self::Error>
	{
		use EndPointAdditionalDescriptorParseError::*;
		use TransferType::*;
		
		const LIBUSB_DT_SS_ENDPOINT_COMPANION: u8 = 0x30;
		
		match descriptor_type
		{
			LIBUSB_DT_SS_ENDPOINT_COMPANION => (),
			
			_ => return Ok(None)
		}
		
		if unlikely!(remaining_bytes.len() < Self::MinimumSize)
		{
			return Err(WrongLength)
		}
		
		#[inline(always)]
		const fn maximum_number_of_packets_that_can_burst_at_a_time(bMaxBurst: u8) -> NonZeroU4
		{
			new_non_zero_u8(bMaxBurst + 1)
		}
		
		let bMaxBurst = remaining_bytes.u8_unadjusted(0);
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
		
		let bmAttributes = remaining_bytes.u8_unadjusted(1);
		let wBytesInterval = remaining_bytes.u16_unadjusted(2);
		let mut consumed_length = Self::reduce_b_length_to_descriptor_body_length(bLength);
		match self.transfer_type
		{
			Control { .. } => (),
			
			Interrupt { ref mut super_speed, .. } =>
			{
				*super_speed = Some
				(
					SuperSpeedInterrupt
					{
						maximum_number_of_packets_that_can_burst_at_a_time: maximum_number_of_packets_that_can_burst_at_a_time(bMaxBurst),
						
						total_number_of_bytes_transfered_every_service_interval: wBytesInterval,
					}
				);
			}
			
			Bulk { ref mut super_speed, .. } =>
			{
				*super_speed = Some
				(
					SuperSpeedBulk
					{
						maximum_number_of_packets_that_can_burst_at_a_time: maximum_number_of_packets_that_can_burst_at_a_time(bMaxBurst),
						
						maximum_streams: match bmAttributes & 0b0001_1111
						{
							0 => None,
							
							maximum_streams @ 1 ..= 16 => Some(BulkMaximumStreamsExponent(new_non_zero_u8(maximum_streams))),
							
							maximum_streams @ _ => return Err(InvalidMaximumStreams { maximum_streams }),
						}
					}
				);
			}
			
			Isochronous { ref mut super_speed, .. } =>
			{
				let bMaxBurst_plus_one = (bMaxBurst + 1) as u32;
				
				// If this field is set to one then a SuperSpeedPlus Isochronous Endpoint Companion descriptor shall immediately follow this descriptor.
				let has_ssp_iso_companion = (bmAttributes & 0b1000_0000) != 0;
				let super_speed_isochronous = if has_ssp_iso_companion
				{
					if unlikely!(wBytesInterval != 1)
					{
						return Err(BytesIntervalMustBeOneIfAnIsochronousEndPointHasASuperSpeedPlusIsochronousEndPointCompanionIndicated)
					}
					
					let dwBytesPerInterval = Self::parse_super_speed_plus_isochronous_end_point_companion_descriptor(remaining_bytes)?;
					consumed_length += Self::CompanionMinimumSize;
					
					SuperSpeedIsochronous
					{
						maximum_number_of_packets_that_can_burst_at_a_time: new_non_zero_u32(dwBytesPerInterval / bMaxBurst_plus_one / (self.maximum_packet_size as u32)),
						
						total_number_of_bytes_transfered_every_service_interval: dwBytesPerInterval,
					}
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
					
					SuperSpeedIsochronous
					{
						maximum_number_of_packets_that_can_burst_at_a_time: new_non_zero_u32(mult_plus_1 * bMaxBurst_plus_one),
						
						total_number_of_bytes_transfered_every_service_interval: wBytesInterval as u32,
					}
				};
				
				*super_speed = Some(super_speed_isochronous);
			}
		}
		
		Ok(Some((EndPointAdditionalDescriptor::SuperSpeedEndPointCompanion, consumed_length)))
	}
}

impl<'a> EndPointAdditionalDescriptorParser<'a>
{
	const MinimumSize: usize = 4;
	
	const CompanionMinimumSize: usize = 8;
	
	#[inline(always)]
	fn parse_super_speed_plus_isochronous_end_point_companion_descriptor(remaining_bytes: &[u8]) -> Result<u32, EndPointAdditionalDescriptorParseError>
	{
		use EndPointAdditionalDescriptorParseError::*;
		
		let remaining_bytes = remaining_bytes.get_unchecked_range_safe(Self::MinimumSize .. );
		
		if unlikely!(remaining_bytes.len() == 0)
		{
			return Err(ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorMissing)
		}
		
		let bDescriptorType = remaining_bytes.u8_unadjusted(1);
		if unlikely!(bDescriptorType != 49)
		{
			return Err(ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorTypeWrong { bDescriptorType })
		}
		
		if unlikely!(remaining_bytes.len() < Self::CompanionMinimumSize)
		{
			return Err(ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorWrongLength)
		}
		
		let bLength = remaining_bytes.u8_unadjusted(0);
		if unlikely!((bLength as usize) < Self::CompanionMinimumSize)
		{
			return Err(ImmediatelyFollowingSuperSpeedPlusIsochronousEndPointCompanionDescriptorTooShort)
		}
		let _wReserved = remaining_bytes.u16_unadjusted(2);
		
		Ok(remaining_bytes.u32_unadjusted(4))
	}
}
