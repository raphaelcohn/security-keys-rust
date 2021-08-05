// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// USB end point transfer type.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum TransferType
{
	/// Control endpoint.
	Control
	{
		/// Negative Acknowledgment (NAK) Rate; `None` means the endpoint never negatively acknowledges.
		///
		/// `Some(negative_acknowledgment_rate)` indicates 1 NAK each `negative_acknowledgment_rate` number of microframes.
		///
		/// A microframe is 125 μs.
		///
		/// Meaningless for Enhanced SuperSpeed.
		/// Meaningless if `Direction::In`.
		polling_negative_acknowledgment_rate: Option<NonZeroU8>,
	},
	
	/// Bulk endpoint.
	Bulk
	{
		/// Direction.
		direction: Direction,
		
		/// This value is not validated except as non-zero.
		///
		/// Negative Acknowledgment (NAK) Rate; `None` means the endpoint never negatively acknowledges.
		///
		/// `Some(negative_acknowledgment_rate)` indicates 1 NAK each `negative_acknowledgment_rate` number of microframes.
		///
		/// A microframe is 125 μs.
		///
		/// Meaningless for Enhanced SuperSpeed.
		/// Meaningless if `Direction::In`.
		polling_negative_acknowledgment_rate: NonZeroU8,
	},
	
	/// Isochronous endpoint.
	Isochronous
	{
		/// Direction.
		direction: Direction,
		
		/// This value is not validated except as non-zero.
		///
		/// Value is between 1 to 16 inclusive and is the number of 125 μs units for Enhanced SuperSpeed.
		/// Value is between 1 to 16 inclusive and is the number of 125 μs units for Full and High speed.
		/// Value is meaningless for Low speed.
		///
		/// The polling period is thus `2^(polling_interval_for_servicing_the_end_point_for_data_transfers - 1)`.
		polling_interval_for_servicing_the_end_point_for_data_transfers: NonZeroU8,
		
		/// Synchronization type.
		synchronization_type: IschronousTransferSynchronizationType,
		
		/// Usage type.
		usage_type: IschronousTransferUsageType,
		
		#[allow(missing_docs)]
		additional_transaction_opportunities_per_microframe: AdditionalTransactionOpportunitiesPerMicroframe,
	},
	
	/// Interrupt endpoint.
	Interrupt
	{
		/// Direction.
		direction: Direction,
		
		/// This value is not validated except as non-zero.
		///
		/// Value is between 1 to 16 inclusive and is the number of 125 μs units for Enhanced SuperSpeed if the usage_type is Periodic.
		/// Value is between 8 to 16 inclusive and is the number of 125 μs units for Enhanced SuperSpeed if the usage_type is Notification.
		/// Value is between 1 to 16 inclusive and is the number of 125 μs units for High speed.
		/// Value is between 1 to 255 inclusive and is the number of 1 millisecond units for Low and Full speed.
		///
		/// The polling period is thus `2^(polling_interval_for_servicing_the_end_point_for_data_transfers - 1)` for High Speed and Enhanced SuperSpeed, and just as-is for Low and FUll speed.
		polling_interval_for_servicing_the_end_point_for_data_transfers: NonZeroU8,
		
		#[allow(missing_docs)]
		additional_transaction_opportunities_per_microframe: AdditionalTransactionOpportunitiesPerMicroframe,
		
		/// Only defined for USB 3.0 and later.
		usage_type: Option<InterruptTransferUsageType>,
	},
}

impl TransferType
{
	#[inline(always)]
	pub(super) fn parse(end_point_descriptor: &libusb_endpoint_descriptor, maximum_supported_usb_version: Version) -> Result<Self, TransferTypeParseError>
	{
		use TransferTypeParseError::*;
		
		#[inline(always)]
		fn non_zero_interval(bInterval: u8) -> Result<NonZeroU8, TransferTypeParseError>
		{
			if bInterval == 0
			{
				Err(IntervalIsZero)
			}
			else
			{
				Ok(new_non_zero_u8(bInterval))
			}
		}
		
		let bInterval = end_point_descriptor.bInterval;
		
		use TransferType::*;
		let bmAttributes = end_point_descriptor.bmAttributes;
		Ok
		(
			match bmAttributes & LIBUSB_TRANSFER_TYPE_MASK
			{
				LIBUSB_TRANSFER_TYPE_CONTROL => Control
				{
					polling_negative_acknowledgment_rate: NonZeroU8::new(bInterval),
				},
				
				LIBUSB_TRANSFER_TYPE_BULK => Bulk
				{
					direction: Direction::from(end_point_descriptor),
					
					polling_negative_acknowledgment_rate: non_zero_interval(bInterval)?,
				},
				
				LIBUSB_TRANSFER_TYPE_ISOCHRONOUS => Isochronous
				{
					direction: Direction::from(end_point_descriptor),
					
					polling_interval_for_servicing_the_end_point_for_data_transfers: non_zero_interval(bInterval)?,
					
					synchronization_type: IschronousTransferSynchronizationType::parse(bmAttributes),
					
					usage_type: IschronousTransferUsageType::parse(bmAttributes)?,
					
					additional_transaction_opportunities_per_microframe: Self::additional_transaction_opportunities_per_microframe(end_point_descriptor),
				},
				
				LIBUSB_TRANSFER_TYPE_INTERRUPT => Interrupt
				{
					direction: Direction::from(end_point_descriptor),
					
					polling_interval_for_servicing_the_end_point_for_data_transfers: non_zero_interval(bInterval)?,
				
					usage_type: if maximum_supported_usb_version.is_3_0_or_greater()
					{
						use InterruptTransferUsageType::*;
						Some
						(
							match (bmAttributes & 0b0011_0000) >> 4
							{
								0 => Periodic,
								
								1 => Notification,
								
								2 | 3 => return Err(ReservedInterruptUsageType),
								
								_ => unreachable!(),
							}
						)
					}
					else
					{
						None
					},
					
					additional_transaction_opportunities_per_microframe: Self::additional_transaction_opportunities_per_microframe(end_point_descriptor),
				},
				
				_ => unreachable!("Bits have been masked"),
			}
		)
	}
	
	// TODO: Fix for USB 3.0
	#[inline(always)]
	fn additional_transaction_opportunities_per_microframe(end_point_descriptor: &libusb_endpoint_descriptor) -> AdditionalTransactionOpportunitiesPerMicroframe
	{
		let max_packet_size = end_point_descriptor.wMaxPacketSize;
		unsafe { transmute(((max_packet_size >> 11) & 0b11) as u8) }
	}
}
