// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Represents an end point.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum EndPoint
{
	#[allow(missing_docs)]
	Control
	{
		common: EndPointCommon,
		
		/// Negative Acknowledgment (NAK) Rate; `None` means the endpoint never negatively acknowledges.
		///
		/// `Some(negative_acknowledgment_rate)` indicates 1 NAK each `negative_acknowledgment_rate` number of microframes.
		///
		/// A microframe is 125 μs.
		///
		/// Meaningless for Enhanced SuperSpeed.
		polling_negative_acknowledgment_rate: Option<NonZeroU8>,
	},
	
	#[allow(missing_docs)]
	Directional(DirectionalEndPoint),
}

impl EndPoint
{
	#[inline(always)]
	pub(crate) fn parse(end_point_descriptor: &libusb_endpoint_descriptor, maximum_supported_usb_version: Version, string_finder: &StringFinder, speed: Option<Speed>, end_points: &mut WrappedIndexMap<EndPointNumber, Self>) -> Result<DeadOrAlive<()>, EndPointParseError>
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
		
		let end_point_number = bEndpointAddress & 0b0000_1111;
		
		let mut transfer_type = DirectionalTransferType::parse(end_point_descriptor, maximum_supported_usb_version, speed).map_err(TransferType)?;
		
		let common = return_ok_if_dead!(EndPointCommon::parse(end_point_descriptor, string_finder, bLength, &mut transfer_type)?);
		
		use EndPoint::*;
		match transfer_type
		{
			Left(polling_negative_acknowledgment_rate) =>
			{
				let end_point = Control
				{
					polling_negative_acknowledgment_rate,
				
					common,
				};
				let outcome = end_points.insert(end_point_number, end_point);
				if unlikely!(outcome.is_some())
				{
					return Err(ControlEndPointIsDuplicate { end_point_number })
				}
			},
			
			Right((direction, transfer_type)) =>
			{
				use Entry::*;
				use DirectionalEndPoint::*;
				match end_points.entry(end_point_number)
				{
					Vacant(vacant) =>
					{
						let _ = vacant.insert
						(
							Directional
							(
								match direction
								{
									Direction::In => In { in_: EndPointCommonAndDirectionalTransferType::new(common, transfer_type) },
									
									Direction::Out => Out { out: EndPointCommonAndDirectionalTransferType::new(common, transfer_type) },
								}
							),
						);
					},
					
					Occupied(mut occupied) => match (occupied.get(), direction)
					{
						(Directional(In { in_ }), Direction::Out) =>
						{
							*occupied.get_mut() = Directional
							(
								InAndOut
								{
									in_: in_.clone(),
								
									out: EndPointCommonAndDirectionalTransferType::new(common, transfer_type),
								}
							);
						}
						
						(Directional(Out { out }), Direction::In) =>
						{
							*occupied.get_mut() = Directional
							(
								InAndOut
								{
									in_: EndPointCommonAndDirectionalTransferType::new(common, transfer_type),
								
									out: out.clone(),
								}
							);
						}
						
						(Directional(In { .. }), Direction::In) => return Err(ControlPointAlreadyIn { end_point_number }),
						
						(Directional(Out { .. }), Direction::Out) => return Err(ControlPointAlreadyOut { end_point_number }),
						
						(Directional(InAndOut { .. }), _) => return Err(ControlPointAlreadyInAndOut { end_point_number, direction }),
						
						(Control { .. }, _) => return Err(ControlEndPointsCanNotAlsoBeDirectional { end_point_number }),
					}
				}
			}
		}
		
		Ok(Alive(()))
	}
}
