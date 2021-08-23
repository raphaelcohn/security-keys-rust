// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio function category; see Device Class for Audio Release 2.0, Section 3.9 Audio Function Category, page 20.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Version2AudioFunctionCategory
{
	#[allow(missing_docs)]
	Undefined,
	
	#[allow(missing_docs)]
	DesktopSpeaker,
	
	#[allow(missing_docs)]
	HomeTheater,
	
	#[allow(missing_docs)]
	Microphone,
	
	#[allow(missing_docs)]
	Headset,
	
	#[allow(missing_docs)]
	Telephone,
	
	#[allow(missing_docs)]
	Converter,
	
	#[allow(missing_docs)]
	VoiceRecorderOrSoundRecorder,
	
	#[allow(missing_docs)]
	InputOutputBox,
	
	#[allow(missing_docs)]
	MusicalInstrument,
	
	#[allow(missing_docs)]
	ProfessionalAudio,
	
	#[allow(missing_docs)]
	AudioVideo,
	
	#[allow(missing_docs)]
	ControlPanel,
	
	#[allow(missing_docs)]
	Reserved
	{
		code: u8,
	},
	
	#[allow(missing_docs)]
	Other,
}
