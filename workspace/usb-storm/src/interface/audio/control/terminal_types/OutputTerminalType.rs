// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Terminal type.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub enum OutputTerminalType
{
	Usb(UsbTerminalType),

	Output(OutputSpecificTerminalType),

	Bidirectional(BidirectionalTerminalType),

	Telephony(TelephonyTerminalType),

	External(ExternalTerminalType),

	EmbeddedFunction(OutputEmbeddedFunctionTerminalType),

	Unknown(u16),
}

impl OutputTerminalType
{
	#[inline(always)]
	pub(super) fn parse<E: error::Error>(value: u16, error: E) -> Result<Self, E>
	{
		use OutputTerminalType::*;
		
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
				0x00 => return Err(error),
				0x01 => return Err(error),
				0x02 => return Err(error),
				0x03 => return Err(error),
				0x04 => return Err(error),
				0x05 => return Err(error),
				0x06 => return Err(error),
				_ => Unknown(value),
			},
			
			0x03 => match bottom_byte
			{
				0x00 => Output(OutputSpecificTerminalType::Undefined),
				0x01 => Output(OutputSpecificTerminalType::Speaker),
				0x02 => Output(OutputSpecificTerminalType::Headphones),
				0x03 => Output(OutputSpecificTerminalType::HeadMountedDisplayAudio),
				0x04 => Output(OutputSpecificTerminalType::DesktopSpeaker),
				0x05 => Output(OutputSpecificTerminalType::RoomSpeaker),
				0x06 => Output(OutputSpecificTerminalType::CommunicationSpeaker),
				0x07 => Output(OutputSpecificTerminalType::LowFrequencyEffectsSpeaker),
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
				0x00 => EmbeddedFunction(OutputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::Undefined)),
				0x01 => EmbeddedFunction(OutputEmbeddedFunctionTerminalType::LevelCalibrationNoiseSource),
				0x02 => EmbeddedFunction(OutputEmbeddedFunctionTerminalType::EqualizationNoise),
				0x03 => return Err(error),
				0x04 => EmbeddedFunction(OutputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::DigitalAudioTape)),
				0x05 => EmbeddedFunction(OutputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::DigitalCompactCassette)),
				0x06 => EmbeddedFunction(OutputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::CompressedAudioPlayer)),
				0x07 => EmbeddedFunction(OutputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::AnalogAudioTape)),
				0x08 => return Err(error),
				0x09 => return Err(error),
				0x0A => return Err(error),
				0x0B => return Err(error),
				0x0C => return Err(error),
				0x0D => return Err(error),
				0x0E => return Err(error),
				0x0F => return Err(error),
				0x10 => return Err(error),
				0x11 => EmbeddedFunction(OutputEmbeddedFunctionTerminalType::RadioTransmitter),
				0x12 => EmbeddedFunction(OutputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::MultitrackRecorder)),
				0x13 => EmbeddedFunction(OutputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::Synthesizer)),
				0x14 => EmbeddedFunction(OutputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::Piano)),
				0x15 => EmbeddedFunction(OutputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::Guitar)),
				0x16 => EmbeddedFunction(OutputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::PercussionInstrument)),
				0x17 => EmbeddedFunction(OutputEmbeddedFunctionTerminalType::Common(CommonEmbeddedFunctionTerminalType::UndefinedMusicalInstrument)),
				_ => Unknown(value),
			},
			
			0x08 ..= 0xFF => Unknown(value),
		};
		
		Ok(parsed)
	}
}
