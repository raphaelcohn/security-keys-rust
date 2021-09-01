// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Audio format.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum Version1AudioFormat
{
	TypeI(Version1TypeIAudioFormat),
	
	TypeII(Version1TypeIIAudioFormat),
	
	TypeIII(Version1TypeIIIAudioFormat),
	
	Unrecognized(u16),
}

impl Version1AudioFormat
{
	const TypeIIUndefined: u16 = 0x1000;
	
	const TypeIIMPEG: u16 = 0x1001;
	
	const TypeIIAC_3: u16 = 0x1002;
	
	#[allow(unused_qualifications)]
	#[inline(always)]
	fn parse(wFormatTag: u16) -> Self
	{
		use Version1AudioFormat::*;
		use Version1TypeIAudioFormat::*;
		use Version1TypeIIAudioFormat::*;
		use Version1TypeIIIAudioFormat::*;
		
		match wFormatTag
		{
			0x0000 => TypeI(Version1TypeIAudioFormat::Undefined),
			
			0x0001 => TypeI(PCM),
			
			0x0002 => TypeI(PCM8),
			
			0x0003 => TypeI(IeeeFloat),
			
			0x0004 => TypeI(ALaw),
			
			0x0005 => TypeI(MuLaw),
			
			Self::TypeIIUndefined => TypeII(Version1TypeIIAudioFormat::Undefined),
			
			Self::TypeIIMPEG => TypeII(MPEG),
			
			Self::TypeIIAC_3 => TypeII(AC_3),
			
			0x2000 => TypeIII(Version1TypeIIIAudioFormat::Undefined),
			
			0x2001 => TypeIII(Iec1937_AC_3),
			
			0x2002 => TypeIII(Iec1937_MPEG_1_Layer_1),
			
			0x2003 => TypeIII(Iec1937_MPEG_1_Layer_2),
			
			0x2004 => TypeIII(Iec1937_MPEG_2_Extended),
			
			0x2005 => TypeIII(Iec1937_MPEG_2_Layer_1_LS),
			
			0x2006 => TypeIII(Iec1937_MPEG_2_Layer_2_LS),
			
			_ => Unrecognized(wFormatTag),
		}
	}
}
