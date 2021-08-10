// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// See Device Class for Audio, Release 3.0-Errate, Appendix A.7, Audio Function Category Codes.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum AudioFunctionCategory
{
	/// `FUNCTION_SUBCLASS_UNDEFINED`.
	FunctionSubclassUndefined,
	
	/// `DESKTOP_SPEAKER`.
	DesktopSpeaker,
	
	/// `HOME_THEATER`.
	HomeTheatre,
	
	/// `MICROPHONE`.
	Microphone,
	
	/// `HEADSET`.
	Headset,
	
	/// `TELEPHONE`.
	Telephone,
	
	/// `CONVERTER`.
	Converter,
	
	/// `VOICE/SOUND_RECORDER`.
	VoiceOrSoundRecorder,
	
	/// `I/O_BOX`.
	InputOutputBox,
	
	/// `MUSICAL_INSTRUMENT`.
	MusicalInstrutment,
	
	/// `PRO-AUDIO`.
	ProAudio,
	
	/// `AUDIO/VIDEO`.
	AudioOrVideo,
	
	/// `CONTROL_PANEL`.
	ControlPanell,
	
	/// `HEADPHONE`.
	Headphone,
	
	/// `GENERIC_SPEAKER`.
	GenericSpeaker,
	
	/// `HEADSET_ADAPTER`.
	HeadsetAdapter,
	
	/// `SPEAKERPHONE`.
	Speakerphone,
	
	/// `OTHER`.
	Other,
	
	/// Reserved.
	Reserved(u8),
}
