// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SmartCardInterfaceAdditionalDescriptor
{
	/// If the protocol is `BulkTransfer`, then:-
	///
	/// * A CCID shall support a minimum of two endpoints in addition to the default (control) endpoint: one bulk-out and one bulk-in.
	/// * A CCID that reports ICC insertion or removal events must also support an interrupt endpoint (interrupt-in).
	protocol: SmartCardProtocol,
	
	/// `bDescriptorType`.
	has_vendor_specific_descriptor_type: bool,

	/// `bcdCCID`.
	version: UsbVersion,
	
	/// `bMaxSlotIndex`.
	///
	/// Add 1 to get the maximum number of slots.
	maximum_slot_index: u8,
	
	/// `bVoltageSupport`.
	voltage_support: BitFlags<VoltageSupport>,
	
	/// `dwProtocols`.
	iso_protocols: BitFlags<IsoProtocol>,
	
	/// Example: 3.58 MHz is encoded as the integer value 3580.
	///
	/// `dwDefaultClock`.
	default_clock_frequency: Kilohertz,
	
	/// `dwMaximumClock`.
	inclusive_maximum_clock_frequency: Kilohertz,
	
	/// `None` means all clock frequencies between `default_clock_frequency` and `inclusive_maximum_clock_frequency` are supported.
	///
	/// `bNumClockSupported`.
	number_of_clock_frequencies_supported: Option<NonZeroU8>,
	
	/// Example: 115.2Kbps is encoded as 115200.
	///
	/// `dwDataRate`.
	default_data_rate: Baud,
	
	/// `dwMaxDataRate`.
	inclusive_maximum_data_rate: Baud,
	
	/// `None` means all data rates between `default_data_rate` and `inclusive_maximum_data_rate` are supported.
	///
	/// `bNumDataRatesSupported`.
	number_of_data_rates_supported: Option<NonZeroU8>,
	
	/// `dwMaxIFSD`.
	maximum_ifsd_for_protocol_t_1: u32,
	
	/// `dwSynchProtocols`.
	synchronization_protocols: BitFlags<SynchronizationProtocol>,
	
	/// `dwMechanical`.
	mechanical_features: BitFlags<MechanicalFeature>,
	
	/// `dwFeatures`.
	features: Features,

	/// For extended APDU level the value shall be between 261 + 10\* and 65544 + 10\*, otherwise the minimum value is the `wMaxPacketSize` of the Bulk-OUT endpoint.
	///
	/// \* The maximum size of the extended APDU header and footer.
	///
	/// `dwMaxCCIDMessageLength`.
	maximum_message_length: u32,

	/// Significant only for CCID that offers an APDU level for exchanges.
	/// Indicates the default class value used by the CCID when it sends a Get Response command to perform the transportation of an APDU by T=0 protocol.
	/// Value 0xFF indicates that the CCID echoes the class of the APDU.
	///
	/// `bClassGetResponse`.
	get_response_class: u8,

	/// Significant only for CCID that offers an extended APDU level for exchanges.
	/// Indicates the default class value used by the CCID when it sends an Envelope command to perform the transportation of an extended APDU by T=0 protocol.
	/// Value 0xFF indicates that the CCID echoes the class of the APDU.
	///
	/// `bClassEnvelope`.
	envelope_class: u8,

	/// `wLcdLayout`.
	lcd_layout: Option<LcdLayout>,

	/// `bPINSupport`.
	pin_support: BitFlags<PinSupport>,

	/// `bMaxCCIDBusySlots`.
	maximum_slots_that_can_be_simultaneously_used: NonZeroU8,
}

impl SmartCardInterfaceAdditionalDescriptor
{
	const Length: usize = 54;
	
	const AdjustedLength: usize = Self::Length - LengthAdjustment;
	
	#[inline(always)]
	pub(super) fn extra_has_matching_length(extra: Option<&[u8]>) -> bool
	{
		if let Some(extra) = extra
		{
			extra.len() == Self::Length
		}
		else
		{
			false
		}
	}
	
	#[inline(always)]
	pub(super) fn last_end_point_matches<'a, 'b: 'a>(interface_descriptor: &'a InterfaceDescriptor<'b>) -> Option<(&'a [u8], EndPointNumber)>
	{
		#[inline(always)]
		fn last_end_point<'a, 'b: 'a>(interface_descriptor: &'a InterfaceDescriptor<'b>) -> Option<EndpointDescriptor<'a>>
		{
			let mut last_end_point = None;
			for end_point in interface_descriptor.endpoint_descriptors()
			{
				last_end_point = Some(end_point)
			}
			last_end_point
		}
		
		if let Some(last_end_point) = last_end_point(interface_descriptor)
		{
			let extra = last_end_point.extra();
			if SmartCardInterfaceAdditionalDescriptor::extra_has_matching_length(extra)
			{
				return Some((extra.unwrap(), last_end_point.number()))
			}
		}
		
		None
	}
	
	#[inline(always)]
	pub(super) fn parse(protocol: SmartCardProtocol, has_vendor_specific_descriptor_type: bool, bytes: &[u8; SmartCardInterfaceAdditionalDescriptor::AdjustedLength]) -> Result<Self, SmartCardInterfaceAdditionalDescriptorParseError>
	{
		Ok
		(
			Self
			{
				protocol,
				
				has_vendor_specific_descriptor_type,
			
				version: UsbVersion::from(bytes.u16::<3>()),
				
				maximum_slot_index: bytes.u8::<4>(),
				
				voltage_support: BitFlags::from_bits_truncate(bytes.u8::<5>()),
	
				iso_protocols: BitFlags::from_bits_truncate(bytes.u32::<6>()),
			
				default_clock_frequency: bytes.kilohertz::<10>(),
			
				inclusive_maximum_clock_frequency: bytes.kilohertz::<14>(),
				
				number_of_clock_frequencies_supported: bytes.optional_non_zero_u8::<18>(),
				
				default_data_rate: bytes.baud::<19>(),
				
				inclusive_maximum_data_rate: bytes.baud::<23>(),
				
				number_of_data_rates_supported: bytes.optional_non_zero_u8::<27>(),
				
				maximum_ifsd_for_protocol_t_1: bytes.u32::<28>(),
				
				synchronization_protocols: BitFlags::from_bits_truncate(bytes.u32::<32>()),
				
				mechanical_features: BitFlags::from_bits_truncate(bytes.u32::<36>()),
				
				features: Features::parse(bytes.u32::<40>())?,
				
				maximum_message_length: bytes.u32::<44>(),
				
				get_response_class: bytes.u8::<48>(),
				
				envelope_class: bytes.u8::<49>(),
				
				lcd_layout: LcdLayout::from(bytes.u16::<50>()),
				
				pin_support: BitFlags::from_bits_truncate(bytes.u8::<52>()),
				
				maximum_slots_that_can_be_simultaneously_used:
				{
					let raw = bytes.u8::<53>();
					if unlikely!(raw == 0)
					{
						new_non_zero_u8(1)
					}
					else
					{
						new_non_zero_u8(raw)
					}
				},
			}
		)
	}
}
