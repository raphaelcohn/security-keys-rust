// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// General
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct General
{
	terminal_link: Option<TerminalEntityIdentifier>,
	
	active_alternate_setting_control: Control,
	
	valid_alternate_setting_control: Control,
	
	audio_data_format_control: Control,
	
	cluster_descriptor_identifier: ClusterDescriptorIdentifier,
	
	audio_formats: WrappedBitFlags<Version3AudioFormat>,
	
	audio_sub_slot_size_in_bytes: u8,
	
	bit_resolution: u8,
	
	control_channel_words_size_in_bytes: u8,
	
	auxillary_protocols: WrappedBitFlags<AuxillaryProtocol>,
}

impl General
{
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn terminal_link(&self) -> Option<TerminalEntityIdentifier>
	{
		self.terminal_link
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn active_alternate_setting_control(&self) -> Control
	{
		self.active_alternate_setting_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn valid_alternate_setting_control(&self) -> Control
	{
		self.valid_alternate_setting_control
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub const fn audio_data_format_control(&self) -> Control
	{
		self.audio_data_format_control
	}
	
	/// "It is allowed to support both Type I and Type III formats in the same Alternate Setting of an AudioStreaming interface as long as the interface is able to unambiguously determine which exact format is currently in use by inspecting the data in the audio stream. Type IV formats can never be mixed with either Type I or Type III formats in the same AudioStreaming interface.
	/// Type IV formats are distinguished from Type I/Type III formats by the absence of a USB endpoint in the AudioStreaming interface.
	/// Type IV formats can never be mixed with either Type I or Type III formats in the same AudioStreaming interface.
	/// Type IV formats are distinguished from Type I/Type III formats by the absence of a USB endpoint in the AudioStreaming interface".
	///
	/// Note that there are no Type II formats.
	#[inline(always)]
	pub const fn audio_formats(&self) -> WrappedBitFlags<Version3AudioFormat>
	{
		self.audio_formats
	}
	
	/// Valid values are 1, 2, 4 and 8 for Simple and Extended Type I formats (if present in `self.audio_formats()`).
	/// Value is always 2 for Simple and Extended Type III formats (if present in `self.audio_formats()`).
	/// Value is should be 0 for Type IV formats (if present in `self.audio_formats()`).
	///
	/// Note that there are no Type II formats.
	#[inline(always)]
	pub const fn audio_sub_slot_size_in_bytes(&self) -> u8
	{
		self.audio_sub_slot_size_in_bytes
	}
	
	/// Valid values are anything for Simple and Extended Type I formats (if present in `self.audio_formats()`).
	/// Value is always 16 for Simple and Extended Type III formats (if present in `self.audio_formats()`).
	/// Value is should be 0 for Type IV formats (if present in `self.audio_formats()`).
	///
	/// Note that there are no Type II formats.
	#[inline(always)]
	pub const fn bit_resolution(&self) -> u8
	{
		self.bit_resolution
	}
	
	/// Value values are anything for Extended Type I formats.
	/// Value should be 0 for all other formats.
	///
	/// Note that there are no Type II formats.
	#[inline(always)]
	pub const fn control_channel_words_size_in_bytes(&self) -> u8
	{
		self.control_channel_words_size_in_bytes
	}
	
	/// These are only valid for Extended Type I and Extended Type III formats.
	#[inline(always)]
	pub const fn auxillary_protocols(&self) -> WrappedBitFlags<AuxillaryProtocol>
	{
		self.auxillary_protocols
	}
	
	#[inline(always)]
	fn parse(bLength: u8, remaining_bytes: &[u8]) -> Result<Self, GeneralParseError>
	{
		use GeneralParseError::*;
		use GeneralControlsParseError::*;
		
		const BLength: u8 = 23;
		let (descriptor_body, descriptor_body_length) = verify_remaining_bytes::<GeneralParseError, BLength>(remaining_bytes, bLength, BLengthIsLessThanMinimum, BLengthExceedsRemainingBytes)?;
		
		let bmControls = descriptor_body.u32(descriptor_index::<4>());
		Ok
		(
			Self
			{
				terminal_link: descriptor_body.optional_non_zero_u8(descriptor_index::<3>()),
				
				active_alternate_setting_control: Control::parse_u32(bmControls, 0, ActiveAlternateSettingControlInvalid)?,
				
				valid_alternate_setting_control: Control::parse_u32(bmControls, 1, ValidAlternateSettingControlInvalid)?,
				
				audio_data_format_control: Control::parse_u32(bmControls, 2, AudioDataFormatControlInvalid)?,
				
				audio_formats: WrappedBitFlags::from_bits_truncate(descriptor_body.u64(descriptor_index::<10>())),
				
				cluster_descriptor_identifier: descriptor_body.u16(descriptor_index::<8>()),
				
				audio_sub_slot_size_in_bytes: descriptor_body.u8(descriptor_index::<18>()),
				
				bit_resolution: descriptor_body.u8(descriptor_index::<19>()),
				
				control_channel_words_size_in_bytes: descriptor_body.u8(descriptor_index::<22>()),
			
				auxillary_protocols: WrappedBitFlags::from_bits_truncate(descriptor_body.u16(descriptor_index::<20>())),
			}
		)
	}
}
