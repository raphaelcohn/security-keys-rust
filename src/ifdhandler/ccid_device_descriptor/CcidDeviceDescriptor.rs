// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CcidDeviceDescriptor<'a>
{
	parent: &'a UsbInterfaceAlternateSetting,
	
	/// If the protocol is `BulkTransfer`, then:-
	///
	/// * A CCID shall support a minimum of two endpoints in addition to the default (control) endpoint: one bulk-out and one bulk-in.
	/// * A CCID that reports ICC insertion or removal events must also support an interrupt endpoint (interrupt-in).
	protocol: CcidProtocol,
	
	/// `bDescriptorType`.
	has_proprietary_descriptor_type: bool,

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

impl<'a> CcidDeviceDescriptor<'a>
{
	pub(crate) const Length: usize = 54;
	
	#[inline(always)]
	pub(super) fn new(parent: &'a UsbInterfaceAlternateSetting, protocol: CcidProtocol, extra: &'a [u8]) -> Result<Self, &'static str>
	{
		let extra = unsafe { & * (extra.as_ptr() as *const [u8; CcidDeviceDescriptor::Length]) };
		
		let bLength = extra.u8(0);
		if unlikely!(bLength != (Self::Length as u8))
		{
			return Err("Length is not 54")
		}
		
		let bDescriptorType = extra.u8(1);
		let has_proprietary_descriptor_type = match bDescriptorType
		{
			0x21 => false,
			
			0xFF => true,
			
			_ => return Err("bDescriptorType is neither standard nor proprietary")
		};
		
		Ok
		(
			Self
			{
				parent,
				
				protocol,
				
				has_proprietary_descriptor_type,
			
				version: UsbVersion::from(extra.u16(3)),
				
				maximum_slot_index: extra.u8(4),
				
				voltage_support: BitFlags::from_bits_truncate(extra.u8(5)),

				iso_protocols: BitFlags::from_bits_truncate(extra.u32(6)),
			
				default_clock_frequency: extra.kilohertz(10),
			
				inclusive_maximum_clock_frequency: extra.kilohertz(14),
				
				number_of_clock_frequencies_supported: extra.optional_non_zero_u8(18),
				
				default_data_rate: extra.baud(19),
				
				inclusive_maximum_data_rate: extra.baud(23),
				
				number_of_data_rates_supported: extra.optional_non_zero_u8(27),
				
				maximum_ifsd_for_protocol_t_1: extra.u32(28),
				
				synchronization_protocols: BitFlags::from_bits_truncate(extra.u32(32)),
				
				mechanical_features: BitFlags::from_bits_truncate(extra.u32(36)),
				
				features: Features::parse(extra.u32(40))?,
				
				maximum_message_length: extra.u32(44),
				
				get_response_class: extra.u8(48),
				
				envelope_class: extra.u8(49),
				
				lcd_layout: LcdLayout::from(extra.u16(50)),
				
				pin_support: BitFlags::from_bits_truncate(extra.u8(52)),
				
				maximum_slots_that_can_be_simultaneously_used:
				{
					let raw = extra.u8(53);
					if raw == 0
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
