// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Class-specific AS interface descriptor.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version2AudioStreamingInterfaceExtraDescriptor
{
	#[allow(missing_docs)]
	General(General),
	
	#[allow(missing_docs)]
	Encoder(Encoder),
	
	#[allow(missing_docs)]
	Decoder(Decoder),
}

impl Version2AudioStreamingInterfaceExtraDescriptor
{
	pub(super) const AS_DESCRIPTOR_UNDEFINED: u8 = 0x00;
	
	pub(super) const AS_GENERAL: u8 = 0x01;
	
	pub(super) const FORMAT_TYPE: u8 = 0x02;
	
	pub(super) const ENCODER: u8 = 0x03;
	
	pub(super) const DECODER: u8 = 0x04;
	
	#[inline(always)]
	pub(super) fn parse_general(bLength: u8, remaining_bytes: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<(Self, usize)>, Version2AudioStreamingInterfaceExtraDescriptorParseError>
	{
		let dead_or_alive = General::parse(bLength, remaining_bytes, string_finder).map_err(Version2AudioStreamingInterfaceExtraDescriptorParseError::GeneralParse)?;
		let (general, consumed_length) = return_ok_if_dead!(dead_or_alive);
		Ok
		(
			Alive
			(
				(
					Version2AudioStreamingInterfaceExtraDescriptor::General(general),
					consumed_length
				)
			)
		)
	}
	
	#[inline(always)]
	pub(super) fn parse_encoder(bLength: u8, remaining_bytes: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<(Self, usize)>, Version2AudioStreamingInterfaceExtraDescriptorParseError>
	{
		let dead_or_alive = Encoder::parse(bLength, remaining_bytes, string_finder).map_err(Version2AudioStreamingInterfaceExtraDescriptorParseError::EncoderParse)?;
		let (encoder, consumed_length) = return_ok_if_dead!(dead_or_alive);
		Ok
		(
			Alive
			(
				(
					Version2AudioStreamingInterfaceExtraDescriptor::Encoder(encoder),
					consumed_length
				)
			)
		)
	}
	
	#[inline(always)]
	pub(super) fn parse_decoder(bLength: u8, remaining_bytes: &[u8], string_finder: &StringFinder) -> Result<DeadOrAlive<(Self, usize)>, Version2AudioStreamingInterfaceExtraDescriptorParseError>
	{
		let dead_or_alive = Decoder::parse(bLength, remaining_bytes, string_finder).map_err(Version2AudioStreamingInterfaceExtraDescriptorParseError::DecoderParse)?;
		let (decoder, consumed_length) = return_ok_if_dead!(dead_or_alive);
		Ok
		(
			Alive
			(
				(
					Version2AudioStreamingInterfaceExtraDescriptor::Decoder(decoder),
					consumed_length
				)
			)
		)
	}
}
