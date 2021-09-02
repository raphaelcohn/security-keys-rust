// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
struct EndPointExtraDescriptorParser<'a>
{
	super_speed_end_point_companion_descriptor_parser: SuperSpeedEndPointCompanionDescriptorParser<'a>,
	
	interface_class: InterfaceClass,
}

impl<'a> DescriptorParser for EndPointExtraDescriptorParser<'a>
{
	type Descriptor = EndPointExtraDescriptor;
	
	type Error = EndPointExtraDescriptorParseError;
	
	#[inline(always)]
	fn parse_descriptor(&mut self, _string_finder: &StringFinder, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<DeadOrAlive<(Self::Descriptor, usize)>>, Self::Error>
	{
		const LIBUSB_DT_SS_ENDPOINT_COMPANION: u8 = 0x30;
		const UsbAttachedStoragePipeDescriptorType: u8 = 0x24;
		const CS_ENDPOINT: u8 = 0x25;
		
		let outcome = match (descriptor_type, self.interface_class)
		{
			(LIBUSB_DT_SS_ENDPOINT_COMPANION, _) => self.super_speed_end_point_companion_descriptor_parser.parse(remaining_bytes, bLength)?,
			
			(UsbAttachedStoragePipeDescriptorType, InterfaceClass::MassStorage(MassStorageSubClass::ScsiTransparentCommandSet(MassStorageProtocol::UsbAttachedScsi))) => UsbAttachedScsiPipeIdentifier::parse(remaining_bytes, bLength)?,
			
			(CS_ENDPOINT, InterfaceClass::Audio(AudioSubClass::Streaming(audio_protocol))) => AudioStreamingIsochronousEndPoint::parse(bLength, remaining_bytes, audio_protocol)?,
			
			_ => None,
		};
		Ok(outcome)
	}
	
	#[inline(always)]
	fn unknown(descriptor_type: DescriptorType, bytes: Vec<u8>) -> Self::Descriptor
	{
		EndPointExtraDescriptor::Unknown { descriptor_type, bytes }
	}
}
