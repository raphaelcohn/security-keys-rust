// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio streaming isochronous end point.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
pub enum AudioStreamingIsochronousEndPoint
{
	#[allow(missing_docs)]
	Version_1_0(Version1AudioStreamingIsochronousEndPoint),
	
	#[allow(missing_docs)]
	Version_2_0(Version2AudioStreamingIsochronousEndPoint),
	
	#[allow(missing_docs)]
	Version_3_0(Version3AudioStreamingIsochronousEndPoint),
	
	#[allow(missing_docs)]
	Undefined
	{
		protocol: AudioProtocol,
		
		data: Vec<u8>,
	}
}

impl AudioStreamingIsochronousEndPoint
{
	#[inline(always)]
	pub(super) fn parse(bLength: u8, remaining_bytes: &[u8], audio_protocol: AudioProtocol) -> Result<Option<DeadOrAlive<(EndPointExtraDescriptor, usize)>>, AudioStreamingIsochronousEndPointParseError>
	{
		use AudioStreamingIsochronousEndPointParseError::*;
		use AudioProtocol::*;
		
		const MinimumBLength: u8 = MinimumStandardUsbDescriptorLength as u8;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<_, MinimumBLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		let descriptor = match audio_protocol
		{
			Version_1_0 => Self::parse_version_1_0(bLength, descriptor_body)?,
			
			Version_2_0 => Self::parse_version_2_0(bLength, descriptor_body)?,
			
			Version_3_0 => Self::parse_version_3_0(bLength, descriptor_body)?,
			
			Unrecognized(_) => return Ok(None),
		};
		Ok(Some(Alive((EndPointExtraDescriptor::AudioStreaming(descriptor), descriptor_body_length))))
	}
	
	#[inline(always)]
	fn parse_version_1_0(bLength: u8, descriptor_body: &[u8]) -> Result<Self, AudioStreamingIsochronousEndPointParseError>
	{
		Self::parse_common(bLength, descriptor_body, AudioProtocol::Version_1_0, Version1AudioStreamingIsochronousEndPoint::parse)
	}
	
	#[inline(always)]
	fn parse_version_2_0(bLength: u8, descriptor_body: &[u8]) -> Result<Self, AudioStreamingIsochronousEndPointParseError>
	{
		Self::parse_common(bLength, descriptor_body, AudioProtocol::Version_2_0, Version2AudioStreamingIsochronousEndPoint::parse)
	}
	
	#[inline(always)]
	fn parse_version_3_0(bLength: u8, descriptor_body: &[u8]) -> Result<Self, AudioStreamingIsochronousEndPointParseError>
	{
		Self::parse_common(bLength, descriptor_body, AudioProtocol::Version_3_0, Version3AudioStreamingIsochronousEndPoint::parse)
	}
	
	#[inline(always)]
	fn parse_common<D: Into<Self>, E: error::Error + Into<AudioStreamingIsochronousEndPointParseError>, VersionParser: FnOnce(u8, &[u8]) -> Result<D, E>>(bLength: u8, descriptor_body: &[u8], protocol: AudioProtocol, version_parser: VersionParser) -> Result<Self, AudioStreamingIsochronousEndPointParseError>
	{
		use AudioStreamingIsochronousEndPointParseError::*;
		
		if unlikely!(bLength < 3)
		{
			return Err(BLengthTooShortToHaveDescriptorSubType)
		}
		
		/// Sic: Yes, DESCRIPTOR, not SUB_DESCRIPTOR; specification is at fault.
		const DESCRIPTOR_UNDEFINED: u8 = 0x00;
		const EP_GENERAL: u8 = 0x01;
		let ok = match descriptor_body.u8(descriptor_index::<2>())
		{
			DESCRIPTOR_UNDEFINED => AudioStreamingIsochronousEndPoint::Undefined
			{
				protocol,
			
				data: Vec::new_from(descriptor_body.get_unchecked_range_safe(descriptor_index::<3>() .. )).map_err(CouldNotAllocateMemoryForUndefined)?,
			},
			
			EP_GENERAL => match version_parser(bLength, descriptor_body)
			{
				Ok(d) => d.into(),
				
				Err(cause) => return Err(cause.into()),
			}
			
			bDescriptorSubType @ _ => return Err(UnrecognizedDescriptorSubType { bDescriptorSubType })
		};
		Ok(ok)
	}
}

impl From<Version1AudioStreamingIsochronousEndPoint> for AudioStreamingIsochronousEndPoint
{
	#[inline(always)]
	fn from(value: Version1AudioStreamingIsochronousEndPoint) -> Self
	{
		AudioStreamingIsochronousEndPoint::Version_1_0(value)
	}
}

impl From<Version2AudioStreamingIsochronousEndPoint> for AudioStreamingIsochronousEndPoint
{
	#[inline(always)]
	fn from(value: Version2AudioStreamingIsochronousEndPoint) -> Self
	{
		AudioStreamingIsochronousEndPoint::Version_2_0(value)
	}
}

impl From<Version3AudioStreamingIsochronousEndPoint> for AudioStreamingIsochronousEndPoint
{
	#[inline(always)]
	fn from(value: Version3AudioStreamingIsochronousEndPoint) -> Self
	{
		AudioStreamingIsochronousEndPoint::Version_3_0(value)
	}
}
