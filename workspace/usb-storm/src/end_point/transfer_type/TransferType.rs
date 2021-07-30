// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// USB end point transfer type.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum TransferType
{
	/// Control endpoint.
	Control,
	
	/// Isochronous endpoint.
	Isochronous
	{
		/// Direction.
		direction: Direction,
		
		/// Synchronization type.
		synchronization_type: IschronousTransferSynchronizationType,
		
		/// Usage type.
		usage_type: IschronousTransferUsageType,
		
		additional_transaction_opportunities_per_microframe: AdditionalTransactionOpportunitiesPerMicroframe,
	},
	
	/// Bulk endpoint.
	Bulk
	{
		/// Direction.
		direction: Direction
	},
	
	/// Interrupt endpoint.
	Interrupt
	{
		/// Direction.
		direction: Direction,
		
		additional_transaction_opportunities_per_microframe: AdditionalTransactionOpportunitiesPerMicroframe,
	},
}

impl TransferType
{
	#[inline(always)]
	pub(super) fn parse(end_point_descriptor: &libusb_endpoint_descriptor) -> Result<Self, TransferTypeParseError>
	{
		/*
		Interval for polling endpoint for data transfers. Expressed in frames or microframes depending on the device operating speed (i.e., either 1 millisecond or 125 μs units).
For full-/high-speed isochronous endpoints, this value
must be in the range from 1 to 16. The bInterval value bInterval-1
is used as the exponent for a 2 value; e.g., a 4-1
bInterval of 4 means a period of 8 (2 ).
For full-/low-speed interrupt endpoints, the value of
this field may be from 1 to 255.
For high-speed interrupt endpoints, the bInterval value
bInterval-1
is used as the exponent for a 2
bInterval of 4 means a period of 8 (2 ). This value must be from 1 to 16.
For high-speed bulk/control OUT endpoints, the bInterval must specify the maximum NAK rate of the endpoint. A value of 0 indicates the endpoint never NAKs. Other values indicate at most 1 NAK each bInterval number of microframes. This value must be in the range from 0 to 255.
		 */
		let _polling_interval = end_point_descriptor.bInterval;
		
		use TransferType::*;
		let bmAttributes = end_point_descriptor.bmAttributes;
		Ok
		(
			match bmAttributes & LIBUSB_TRANSFER_TYPE_MASK
			{
				LIBUSB_TRANSFER_TYPE_CONTROL => Control,
				
				LIBUSB_TRANSFER_TYPE_ISOCHRONOUS => Isochronous
				{
					direction: Direction::from(end_point_descriptor),
					
					synchronization_type: IschronousTransferSynchronizationType::parse(bmAttributes),
					
					usage_type: IschronousTransferUsageType::parse(bmAttributes)?,
					
					additional_transaction_opportunities_per_microframe: Self::additional_transaction_opportunities_per_microframe(end_point_descriptor),
				},
				
				LIBUSB_TRANSFER_TYPE_BULK => Bulk
				{
					direction: Direction::from(end_point_descriptor),
				},
				
				LIBUSB_TRANSFER_TYPE_INTERRUPT => Interrupt
				{
					direction: Direction::from(end_point_descriptor),
					
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
