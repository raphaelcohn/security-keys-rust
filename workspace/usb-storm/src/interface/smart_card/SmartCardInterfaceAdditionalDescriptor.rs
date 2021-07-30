// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A smart card descriptor.
#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmartCardInterfaceAdditionalDescriptor
{
	protocol: SmartCardProtocol,
	
	/// `bDescriptorType`.
	has_vendor_specific_descriptor_type: bool,

	/// `bcdCCID`.
	firmware_version: Version,
	
	/// `bMaxSlotIndex`.
	///
	/// Add 1 to get the maximum number of slots.
	maximum_slot_index: u8,
	
	/// `bVoltageSupport`.
	voltages_supported: BitFlags<VoltageSupport>,
	
	/// `dwProtocols`.
	iso_7816_protocols: BitFlags<Iso7816Protocol>,
	
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
	maximum_ifsd_for_protocol_t_1: Option<u32>,
	
	/// `dwSynchProtocols`.
	synchronization_protocols: BitFlags<SynchronizationProtocol>,
	
	/// `dwMechanical`.
	mechanical_features: BitFlags<MechanicalFeature>,
	
	/// `dwFeatures`.
	features: Features,

	/// For the extended APDU level of exchange this value shall be between 261 + 10\* and 65544 + 10\*, otherwise the minimum value is the `wMaxPacketSize` of the Bulk-OUT endpoint.
	///
	/// \* The maximum size of the extended APDU header and footer.
	///
	/// `dwMaxCCIDMessageLength`.
	maximum_message_length: u32,
	
	unconfigured_classes_for_protocol_t_0: Option<T0ProtocolUnconfiguredClasses>,

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
	
	/// If the protocol is `BulkTransfer`, then:-
	///
	/// * A CCID shall support a minimum of two endpoints in addition to the default (control) endpoint: one bulk-out and one bulk-in.
	/// * A CCID that reports ICC insertion or removal events must also support an interrupt endpoint (interrupt-in).
	#[inline(always)]
	pub const fn protocol(&self) -> SmartCardProtocol
	{
		self.protocol
	}
	
	/// If `true`, then this is a Smart Card that predates standardization.
	#[inline(always)]
	pub const fn has_vendor_specific_descriptor_type(&self) -> bool
	{
		self.has_vendor_specific_descriptor_type
	}
	
	/// Firmware version.
	#[inline(always)]
	pub const fn firmware_version(&self) -> Version
	{
		self.firmware_version
	}
	
	/// Add 1 to get the maximum number of slots.
	#[inline(always)]
	pub const fn maximum_slot_index(&self) -> u8
	{
		self.maximum_slot_index
	}
	
	/// Voltages supported.
	#[inline(always)]
	pub const fn voltages_supported(&self) -> BitFlags<VoltageSupport>
	{
		self.voltages_supported
	}
	
	/// ISO 7816 protocols supported.
	#[inline(always)]
	pub const fn iso_7816_protocols(&self) -> BitFlags<Iso7816Protocol>
	{
		self.iso_7816_protocols
	}
	
	/// Example: 3.58 MHz is encoded as the integer value 3580.
	///
	/// Often the same as `inclusive_maximum_clock_frequency()`, particularly so if `number_of_clock_frequencies_supported()` is `None`.
	#[inline(always)]
	pub const fn default_clock_frequency(&self) -> Kilohertz
	{
		self.default_clock_frequency
	}
	
	/// Example: 3.58 MHz is encoded as the integer value 3580.
	///
	/// Often the same as `default_clock_frequency()`, particularly so if `number_of_clock_frequencies_supported()` is `None`.
	#[inline(always)]
	pub const fn inclusive_maximum_clock_frequency(&self) -> Kilohertz
	{
		self.inclusive_maximum_clock_frequency
	}
	
	/// `None` means all clock frequencies between `default_clock_frequency()` and `inclusive_maximum_clock_frequency()` are supported.
	///
	/// `None` is quite common.
	#[inline(always)]
	pub const fn number_of_clock_frequencies_supported(&self) -> Option<NonZeroU8>
	{
		self.number_of_clock_frequencies_supported
	}
	
	/// Example: 115.2Kbps is encoded as 115200.
	///
	/// Often the same as `inclusive_maximum_data_rate()`, particularly so if `number_of_data_rates_supported()` is `None`.
	#[inline(always)]
	pub const fn default_data_rate(&self) -> Baud
	{
		self.default_data_rate
	}
	
	/// Example: 115.2Kbps is encoded as 115200.
	///
	/// Often the same as `default_data_rate()`, particularly so if `number_of_data_rates_supported()` is `None`.
	#[inline(always)]
	pub const fn inclusive_maximum_data_rate(&self) -> Baud
	{
		self.inclusive_maximum_data_rate
	}
	
	/// `None` means all data rates between `default_data_rate()` and `inclusive_maximum_data_rate()` are supported.
	///
	/// `None` is quite common.
	#[inline(always)]
	pub const fn number_of_data_rates_supported(&self) -> Option<NonZeroU8>
	{
		self.number_of_data_rates_supported
	}
	
	/// `None` if protocol T=1 is not supported.
	#[inline(always)]
	pub const fn maximum_ifsd_for_protocol_t_1(&self) -> Option<u32>
	{
		self.maximum_ifsd_for_protocol_t_1
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn synchronization_protocols(&self) -> BitFlags<SynchronizationProtocol>
	{
		self.synchronization_protocols
	}
	
	/// Very rarely anything other than `empty`.
	#[inline(always)]
	pub const fn mechanical_features(&self) -> BitFlags<MechanicalFeature>
	{
		self.mechanical_features
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn features(&self) -> Features
	{
		self.features
	}
	
	/// For the extended APDU level of exchange this value shall be between 261 + 10\* and 65544 + 10\*, otherwise the minimum value is the `wMaxPacketSize` of the Bulk-OUT endpoint.
	///
	/// \* The maximum size of the extended APDU header and footer.
	#[inline(always)]
	pub const fn maximum_message_length(&self) -> u32
	{
		self.maximum_message_length
	}
	
	/// `None` if protocol T=0 is not supported.
	#[inline(always)]
	pub const fn unconfigured_classes_for_protocol_t_0(&self) -> Option<T0ProtocolUnconfiguredClasses>
	{
		self.unconfigured_classes_for_protocol_t_0
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn lcd_layout(&self) -> Option<LcdLayout>
	{
		self.lcd_layout
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn pin_support(&self) -> BitFlags<PinSupport>
	{
		self.pin_support
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn maximum_slots_that_can_be_simultaneously_used(&self) -> NonZeroU8
	{
		self.maximum_slots_that_can_be_simultaneously_used
	}
	
	#[inline(always)]
	pub(super) fn extra_has_matching_length(extra: &[u8]) -> bool
	{
		extra.len() == Self::Length
	}
	
	#[inline(always)]
	pub(super) fn last_end_point_matches(alternate_setting: &libusb_interface_descriptor) -> Option<R>
	{
		#[inline(always)]
		fn last_end_point(alternate_setting: &libusb_interface_descriptor) -> Option<&libusb_endpoint_descriptor>
		{
			let mut last_end_point = None;
			let endpoint_descriptors = interface_descriptor.endpoint_descriptors();
			for end_point in endpoint_descriptors
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
				return Some(user(extra.unwrap(), last_end_point.number()))
			}
		}
		
		None
	}
	
	#[inline(always)]
	fn parse(protocol: SmartCardProtocol, has_vendor_specific_descriptor_type: bool, bytes: &[u8]) -> Result<Self, SmartCardInterfaceAdditionalDescriptorParseError>
	{
		let iso_7816_protocols = BitFlags::from_bits_truncate(bytes.u32::<6>());
		let features = Features::parse(bytes.u32::<40>(), iso_7816_protocols)?;
		Ok
		(
			Self
			{
				protocol,
				
				has_vendor_specific_descriptor_type,
			
				firmware_version: bytes.version::<2>(),
				
				maximum_slot_index: bytes.u8::<4>(),
				
				voltages_supported: BitFlags::from_bits_truncate(bytes.u8::<5>()),
	
				iso_7816_protocols,
			
				default_clock_frequency: bytes.kilohertz::<10>(),
			
				inclusive_maximum_clock_frequency: bytes.kilohertz::<14>(),
				
				number_of_clock_frequencies_supported: bytes.optional_non_zero_u8::<18>(),
				
				default_data_rate: bytes.baud::<19>(),
				
				inclusive_maximum_data_rate: bytes.baud::<23>(),
				
				number_of_data_rates_supported: bytes.optional_non_zero_u8::<27>(),
				
				maximum_ifsd_for_protocol_t_1: if iso_7816_protocols.contains(Iso7816Protocol::T1)
				{
					Some(bytes.u32::<28>())
				}
				else
				{
					None
				},
				
				synchronization_protocols: BitFlags::from_bits_truncate(bytes.u32::<32>()),
				
				mechanical_features: BitFlags::from_bits_truncate(bytes.u32::<36>()),
				
				features,
				
				maximum_message_length: bytes.u32::<44>(),
				
				unconfigured_classes_for_protocol_t_0: Self::parse_get_response_class_and_envelope_class(bytes, features.level_of_exchange(), iso_7816_protocols)?,
				
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
	
	fn parse_get_response_class_and_envelope_class(bytes: &[u8], level_of_exchange: LevelOfExchange, iso_7816_protocols: BitFlags<Iso7816Protocol>) -> Result<Option<T0ProtocolUnconfiguredClasses>, SmartCardInterfaceAdditionalDescriptorParseError>
	{
		let value = if level_of_exchange.is_apdu_level() && iso_7816_protocols.contains(Iso7816Protocol::T0)
		{
			use self::SmartCardInterfaceAdditionalDescriptorParseError::*;
			
			Some
			(
				T0ProtocolUnconfiguredClasses
				{
					apdu_get_response:
					{
						// Significant only for a CCID that offers an APDU level for exchanges with the T=0 protocol.
						//
						// This is the value of the `CLA` field.
						//
						// Indicates the default class value used by the CCID when it sends a Get Response command to perform the transportation of an APDU by T=0 protocol.
						// Value `0xFF` indicates that the CCID echoes the class of the APDU.
						//
						// Relevant only if:-
						// * T=0 protocol is supported.
						//
						// Values observed in the wild:-
						// * 0x00
						// * 0xFF commonest value
						let bClassGetResponse = bytes.u8::<48>();
						T0ProtocolUnconfiguredClass::parse(bClassGetResponse, UnsupportedClassGetResponse)?
					},
					
					extended_apdu_envelope: if level_of_exchange.is_extended_apdu_level()
					{
						// Significant only for a CCID that offers an extended APDU level for exchanges with the T=0 protocol.
						//
						// This is the value of the `CLA` field.
						//
						// Indicates the default class value used by the CCID when it sends an Envelope command to perform the transportation of an extended APDU by T=0 protocol.
						// Value `0xFF` indicates that the CCID echoes the class of the APDU.
						//
						// Relevant only if:-
						// * T=0 protocol is supported;
						// * An extended APDU level of exhange is supported.
						//
						// Values observed in the wild:-
						// * 0x00
						// * 0x01 Plaenta (0x21AB) RC700-NFC CCID (0x0010); however, this device does not support an extended APDU level of exchange.
						// * 0xFF commonest value
						let bClassEnvelope = bytes.u8::<49>();
						Some(T0ProtocolUnconfiguredClass::parse(bClassEnvelope, UnsupportedClassEnvelope)?)
					}
					else
					{
						None
					},
				}
			)
		}
		else
		{
			None
		};
		Ok(value)
	}
}
