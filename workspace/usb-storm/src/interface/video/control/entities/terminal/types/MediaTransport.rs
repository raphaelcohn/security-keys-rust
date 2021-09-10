// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Media transport.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MediaTransport
{
	transport_modes: Option<WrappedBitFlags<MediaTransportMode>>,
	
	absolute_track_number_control: bool,
	
	media_information_control: bool,
	
	time_code_information_control: bool,
}

impl MediaTransport
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn transport_modes(&self) -> Option<&WrappedBitFlags<MediaTransportMode>>
	{
		self.transport_modes.as_ref()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn absolute_track_number_control(&self) -> bool
	{
		self.absolute_track_number_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn media_information_control(&self) -> bool
	{
		self.media_information_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn time_code_information_control(&self) -> bool
	{
		self.time_code_information_control
	}
	
	#[inline(always)]
	fn parse<const starts_at_index: u8>(bLengthUsize: usize, entity_bytes: &[u8]) -> Result<Self, MediaTransportParseError>
	{
		use MediaTransportParseError::*;
		
		#[inline(always)]
		const fn entity_index_local<const starts_at_index: u8>(relative_index: usize) -> usize
		{
			entity_index_non_constant((starts_at_index as usize) + relative_index)
		}
		
		const SizeOfbmControls: usize = size_of::<u8>();
		const SizeOfbTransportModeSize: usize = size_of::<u8>();
		
		if unlikely!(bLengthUsize < ((starts_at_index as usize) + SizeOfbmControls + SizeOfbTransportModeSize))
		{
			return Err(BLengthTooShort)
		}
		
		let bControlSize = entity_bytes.u8(entity_index_local::<starts_at_index>(0)) as usize;
		if unlikely!(bLengthUsize < ((starts_at_index as usize) + SizeOfbmControls + bControlSize + SizeOfbTransportModeSize))
		{
			return Err(BLengthTooShortToIncludeControls)
		}
		
		let bTransportModeSize = entity_bytes.u8(entity_index_local::<starts_at_index>(SizeOfbmControls + bControlSize)) as usize;
		if unlikely!(bLengthUsize < ((starts_at_index as usize) + SizeOfbmControls + bControlSize + SizeOfbTransportModeSize + bTransportModeSize))
		{
			return Err(BLengthTooShortToIncludeTransportModes)
		}
		
		let controls = entity_bytes.bytes(entity_index_local::<starts_at_index>(SizeOfbmControls), bControlSize);
		let (transport_control, absolute_track_number_control, media_information_control, time_code_information_control) = Self::parse_controls(controls);
		
		let transport_modes = if likely!(transport_control)
		{
			let transport_modes = entity_bytes.bytes(entity_index_local::<starts_at_index>(SizeOfbmControls + bControlSize + SizeOfbTransportModeSize), bTransportModeSize);
			Some(Self::parse_transport_modes(transport_modes))
		}
		else
		{
			None
		};
		
		Ok
		(
			Self
			{
				transport_modes,
				
				absolute_track_number_control,
			
				media_information_control,
			
				time_code_information_control,
			}
		)
	}
	
	#[inline(always)]
	fn parse_controls(controls: &[u8]) -> (bool, bool, bool, bool)
	{
		let byte = if unlikely!(controls.is_empty())
		{
			0x00
		}
		else
		{
			controls.get_unchecked_value_safe(0)
		};
		
		(
			byte & 0b0001 != 0,
			byte & 0b0010 != 0,
			byte & 0b0100 != 0,
			byte & 0b1000 != 0,
		)
	}
	
	#[inline(always)]
	fn parse_transport_modes(transport_modes: &[u8]) -> WrappedBitFlags<MediaTransportMode>
	{
		match transport_modes.len()
		{
			0 => WrappedBitFlags::from_bits_unchecked(0),
			
			1 => WrappedBitFlags::from_bits_unchecked(transport_modes.u8_as_u64(0)),
			
			2 => WrappedBitFlags::from_bits_unchecked(transport_modes.u16_as_u64(0)),
			
			3 => WrappedBitFlags::from_bits_unchecked(transport_modes.u24_as_u64(0)),
			
			4 => WrappedBitFlags::from_bits_unchecked(transport_modes.u32_as_u64(0)),
			
			5 => WrappedBitFlags::from_bits_truncate(transport_modes.u40_as_u64(0)),
			
			6 => WrappedBitFlags::from_bits_truncate(transport_modes.u48_as_u64(0)),
			
			7 => WrappedBitFlags::from_bits_truncate(transport_modes.u56_as_u64(0)),
			
			_ => WrappedBitFlags::from_bits_truncate(transport_modes.u64(0)),
		}
	}
}

