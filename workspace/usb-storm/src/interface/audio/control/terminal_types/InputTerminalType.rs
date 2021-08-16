// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Terminal type.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub enum InputTerminalType
{
	Usb(UsbTerminalType),

	Input(InputSpecificTerminalType),

	Bidirectional(BidirectionalTerminalType),

	Telephony(TelephonyTerminalType),

	External(ExternalTerminalType),

	EmbeddedFunction(InputEmbeddedFunctionTerminalType),

	Unknown(u16),
}

impl InputTerminalType
{
	#[inline(always)]
	pub(super) fn parse<E: error::Error>(value: u16, error: E) -> Result<Self, E>
	{
		use InputTerminalType::*;
		
		let top_byte = ((value & 0xFF00) >> 8) as u8;
		let bottom_byte = (value & 0x00FF) as u8;
		
		let parsed = match top_byte
		{
			0x00 => Unknown(value),
			
			0x01 => match bottom_byte
			{
				0x00 => Usb(UsbTerminalType::Undefined),
				0x01 => Usb(UsbTerminalType::Streaming),
				0xFF => Usb(UsbTerminalType::VendorSpecific),
				_ => Unknown(value),
			},
			
			0x02 => match bottom_byte
			{
				0x00 => Input(InputSpecificTerminalType::Undefined),
				0x01 => Input(InputSpecificTerminalType::Microphone),
				0x02 => Input(InputSpecificTerminalType::DesktopMicrophone),
				0x03 => Input(InputSpecificTerminalType::PersonalMicrophone),
				0x04 => Input(InputSpecificTerminalType::OmnidirectionalMicrophone),
				0x05 => Input(InputSpecificTerminalType::MicrophoneArray),
				0x06 => Input(InputSpecificTerminalType::ProcessingMicrophoneArray),
				_ => Unknown(value),
			},
			
			0x03 => match bottom_byte
			{
				0x00 => return Err(error),
				0x01 => return Err(error),
				0x02 => return Err(error),
				0x03 => return Err(error),
				0x04 => return Err(error),
				0x05 => return Err(error),
				0x06 => return Err(error),
				0x07 => return Err(error),
				_ => Unknown(value),
			},
			
			0x04 => match bottom_byte
			{
				0x00 => Bidirectional(BidirectionalTerminalType::Undefined),
				0x01 => Bidirectional(BidirectionalTerminalType::HandHeldHandset),
				0x02 => Bidirectional(BidirectionalTerminalType::HeadMountedHeadset),
				0x03 => Bidirectional(BidirectionalTerminalType::NoEchoReductionSpeakerphone),
				0x04 => Bidirectional(BidirectionalTerminalType::EchoSuppressingSpeakerphone),
				0x05 => Bidirectional(BidirectionalTerminalType::EchoCancellingSpeakerphone),
				_ => Unknown(value),
			},
			
			0x05 => match bottom_byte
			{
				0x00 => Telephony(TelephonyTerminalType::Undefined),
				0x01 => Telephony(TelephonyTerminalType::PhoneLine),
				0x02 => Telephony(TelephonyTerminalType::Telephone),
				0x03 => Telephony(TelephonyTerminalType::DownLinePhone),
				_ => Unknown(value),
			},
			
			0x06 => match bottom_byte
			{
				0x00 => External(ExternalTerminalType::Undefined),
				0x01 => External(ExternalTerminalType::AnalogConnector),
				0x02 => External(ExternalTerminalType::DigitalAudioConnector),
				0x03 => External(ExternalTerminalType::LineConnector),
				0x04 => External(ExternalTerminalType::LegacyAudioConnector),
				0x05 => External(ExternalTerminalType::SpdifInterface),
				0x06 => External(ExternalTerminalType::Ieee1394DigitalAudioStream),
				0x07 => External(ExternalTerminalType::Ieee1394DigitalAudioStreamSoundtrack),
				0x08 => External(ExternalTerminalType::AlesisDigitalAudioTapeStream),
				0x09 => External(ExternalTerminalType::TascamDigitalInterface),
				0x0A => External(ExternalTerminalType::MultichannelAudioDigitalInterface),
				_ => Unknown(value),
			},
			
			0x07 => match bottom_byte
			{
				0x00 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::Undefined)),
				0x01 => return Err(error),
				0x02 => return Err(error),
				0x03 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::CompactDiscPlayer),
				0x04 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::DigitalAudioTape)),
				0x05 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::DigitalCompactCassette)),
				0x06 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::CompressedAudioPlayer)),
				0x07 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::AnalogAudioTape)),
				0x08 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::AnalogVinylRecordPlater),
				0x09 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::AudioTrackVideoCassetteRecorder),
				0x0A => EmbeddedFunction(InputEmbeddedFunctionTerminalType::AudioTrackVidoDiscPlayer),
				0x0B => EmbeddedFunction(InputEmbeddedFunctionTerminalType::AudioTrackDigialVideoDiscPlayer),
				0x0C => EmbeddedFunction(InputEmbeddedFunctionTerminalType::AudioTrackTelevisionTuner),
				0x0D => EmbeddedFunction(InputEmbeddedFunctionTerminalType::AudioTrackSatelliteReceiver),
				0x0E => EmbeddedFunction(InputEmbeddedFunctionTerminalType::AudioTrackCableTuner),
				0x0F => EmbeddedFunction(InputEmbeddedFunctionTerminalType::AudioTrackDssReceiver),
				0x10 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::RadioReceiver),
				0x11 => return Err(error),
				0x12 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::MultitrackRecorder)),
				0x13 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::Synthesizer)),
				0x14 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::Piano)),
				0x15 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::Guitar)),
				0x16 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::PercussionInstrument)),
				0x17 => EmbeddedFunction(InputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::UndefinedMusicalInstrument)),
				_ => Unknown(value),
			},
			
			0x08 ..= 0xFF => Unknown(value),
		};
		
		Ok(parsed)
	}
}
