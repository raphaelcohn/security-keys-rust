// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Camera.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Camera
{
	optical_zoom: Option<OpticalZoom>,

	controls: WrappedBitFlags<CameraControl>
}

impl Camera
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn optical_zoom(&self) -> Option<&OpticalZoom>
	{
		self.optical_zoom.as_ref()
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn controls(&self) -> WrappedBitFlags<CameraControl>
	{
		self.controls
	}
	
	#[inline(always)]
	pub(super) fn parse(bLengthUsize: usize, entity_bytes: &[u8], specification_version: Version) -> Result<Self, CameraParseError>
	{
		use CameraParseError::*;
		
		const MinimumBLength: usize = 15;
		
		if unlikely!(bLengthUsize < MinimumBLength)
		{
			return Err(BLengthTooShort)
		}
		
		Ok
		(
			Self
			{
				optical_zoom: OpticalZoom::parse(entity_bytes)?,
			
				controls:
				{
					let control_size_information = Self::parse_control_size_information(bLengthUsize, entity_bytes, specification_version)?;
					Self::parse_controls(entity_bytes, control_size_information)
				}
			}
		)
	}
	
	#[inline(always)]
	fn parse_controls(entity_bytes: &[u8], (control_size, bit_mask): (usize, u32)) -> WrappedBitFlags<CameraControl>
	{
		let bmControls = entity_bytes.bytes(entity_index::<15>(), control_size);
		let value = match control_size
		{
			0 => 0,
			
			1 => bmControls.u8_as_u32(0),
			
			2 => bmControls.u16_as_u32(0),
			
			3 => bmControls.u24_as_u32(0),
			
			_ => bmControls.u32(0),
		};
		WrappedBitFlags::from_bits_unchecked(value & bit_mask)
	}
	
	#[inline(always)]
	fn parse_control_size_information(bLengthUsize: usize, entity_bytes: &[u8], specification_version: Version) -> Result<(usize, u32), CameraParseError>
	{
		use CameraParseError::*;
		
		let bControlSize = entity_bytes.u8(entity_index::<14>());
		const AllSpecificationVersionsBitMask: u32 = 0b0000_0110_0111_1111_1111_1111;
		let bit_mask = if specification_version.is_1_5_or_greater()
		{
			if unlikely!(bControlSize != 3)
			{
				return Err(Version_1_5_HasInvalidControlSize { bControlSize })
			}
			const Bits19To21: u32 = 0b0011_1000_0000_0000_0000_0000;
			const BitMask: u32 = AllSpecificationVersionsBitMask | Bits19To21;
			BitMask
		}
		else
		{
			AllSpecificationVersionsBitMask
		};
		
		let control_size = bControlSize as usize;
		const MinimumBLength: usize = 15;
		if unlikely!(bLengthUsize < (MinimumBLength + control_size))
		{
			return Err(BLengthTooShortForControlSize { bControlSize })
		}
		Ok((control_size, bit_mask))
	}
}
