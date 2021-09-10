// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct VideoControlInterfaceExtraDescriptorParser(pub(crate) VideoProtocol);

impl DescriptorParser for VideoControlInterfaceExtraDescriptorParser
{
	type Descriptor = VideoControlInterfaceExtraDescriptor;
	
	type Error = VideoControlInterfaceExtraDescriptorParseError;
	
	#[inline(always)]
	fn parse_descriptor(&mut self, device_connection: &DeviceConnection, bLength: u8, descriptor_type: DescriptorType, remaining_bytes: &[u8]) -> Result<Option<DeadOrAlive<(Self::Descriptor, usize)>>, Self::Error>
	{
		use VideoControlInterfaceExtraDescriptorParseError::*;
		
		match descriptor_type
		{
			CS_INTERFACE => (),
			
			_ => return Ok(None),
		};
		
		if unlikely!(bLength < Self::MinimumBLengthForASubTypedDescriptor)
		{
			return Err(BLengthTooShortForASubTypedDescriptor)
		}
		
		let descriptor = match remaining_bytes.u8(descriptor_index::<2>())
		{
			VC_DESCRIPTOR_UNDEFINED => Self::parse_undefined(remaining_bytes, bLength)?,
			
			VC_HEADER => Self::parse_header(remaining_bytes, bLength, device_connection, self.0)?,
			
			VC_INPUT_TERMINAL => return Err(InputTerminalNotExpected),
			
			VC_OUTPUT_TERMINAL => return Err(OutputTerminalNotExpected),
			
			VC_SELECTOR_UNIT => return Err(SelectorUnitNotExpected),
			
			VC_PROCESSING_UNIT => return Err(ProcessingUnitNotExpected),
			
			VC_EXTENSION_UNIT => return Err(ExtensionUnitNotExpected),
			
			bDescriptorSubType @ _ => return Err(UnrecognizedDescriptorSubType { bDescriptorSubType }),
		};
		Ok(Some(descriptor))
	}
}

impl VideoControlInterfaceExtraDescriptorParser
{
	const SizeOfDescriptorSubType: u8 = size_of::<DescriptorSubType>() as u8;
	
	const MinimumBLengthForASubTypedDescriptor: u8 = (DescriptorHeaderLength as u8) + Self::SizeOfDescriptorSubType;
	
	
	#[inline(always)]
	fn parse_undefined(remaining_bytes: &[u8], bLength: u8) -> Result<DeadOrAlive<(VideoControlInterfaceExtraDescriptor, usize)>, UndefinedVideoControlInterfaceExtraDescriptorParseError>
	{
		use UndefinedVideoControlInterfaceExtraDescriptorParseError::*;
		
		const MinimumBLength: u8 = VideoControlInterfaceExtraDescriptorParser::MinimumBLengthForASubTypedDescriptor;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<_, MinimumBLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		let undefined_bytes = descriptor_body.get_unchecked_range_safe((Self::SizeOfDescriptorSubType as usize) .. );
		let bytes = Vec::new_from(undefined_bytes).map_err(CouldNotAllocateMemoryForBytes)?;
		
		Ok(Alive((VideoControlInterfaceExtraDescriptor::Undefined(bytes), descriptor_body_length)))
	}
	
	#[inline(always)]
	fn parse_header(remaining_bytes: &[u8], bLength: u8, device_connection: &DeviceConnection, video_protocol: VideoProtocol) -> Result<DeadOrAlive<(VideoControlInterfaceExtraDescriptor, usize)>, VideoControlParseError>
	{
		use VideoControlParseError::*;
		
		const MinimumBLength: u8 = 12;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<_, MinimumBLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		let dead_or_alive = VideoControl::parse(descriptor_body, descriptor_body_length, remaining_bytes, device_connection, video_protocol)?;
		let (header, consumed_length) = return_ok_if_dead!(dead_or_alive);
		Ok(Alive((VideoControlInterfaceExtraDescriptor::VideoControl(header), consumed_length)))
	}
}
