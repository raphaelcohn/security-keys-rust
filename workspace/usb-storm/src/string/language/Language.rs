// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Language.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Language
{
	#[allow(missing_docs)]
	Afrikaans,
	
	#[allow(missing_docs)]
	Albanian,
	
	#[allow(missing_docs)]
	Arabic(ArabicSubLanguage),
	
	#[allow(missing_docs)]
	Armenian,
	
	#[allow(missing_docs)]
	Assamese,
	
	#[allow(missing_docs)]
	Azeri(CyrillicOrLatinSubLanguage),
	
	#[allow(missing_docs)]
	Basque,
	
	#[allow(missing_docs)]
	Belarussian,
	
	#[allow(missing_docs)]
	Bengali,
	
	#[allow(missing_docs)]
	Bulgarian,
	
	#[allow(missing_docs)]
	Burmese,
	
	#[allow(missing_docs)]
	Catalan,
	
	#[allow(missing_docs)]
	Chinese(ChineseSubLanguage),
	
	#[allow(missing_docs)]
	Croatian,
	
	#[allow(missing_docs)]
	Czech,
	
	#[allow(missing_docs)]
	Danish,
	
	#[allow(missing_docs)]
	Dutch(DutchSubLanguage),
	
	#[allow(missing_docs)]
	English(EnglishSubLanguage),
	
	#[allow(missing_docs)]
	Estonian,
	
	#[allow(missing_docs)]
	Faeroese,
	
	#[allow(missing_docs)]
	Farsi,
	
	#[allow(missing_docs)]
	Finnish,
	
	#[allow(missing_docs)]
	French(FrenchSubLanguage),
	
	#[allow(missing_docs)]
	Georgian,
	
	#[allow(missing_docs)]
	German(GermanSubLanguage),
	
	#[allow(missing_docs)]
	Greek,
	
	#[allow(missing_docs)]
	Gujarati,
	
	#[allow(missing_docs)]
	Hebrew,
	
	#[allow(missing_docs)]
	Hindi,
	
	#[allow(missing_docs)]
	Hungarian,
	
	#[allow(missing_docs)]
	Icelandic,
	
	#[allow(missing_docs)]
	Indonesian,
	
	#[allow(missing_docs)]
	Italian(ItalianSubLanguage),
	
	#[allow(missing_docs)]
	Japanese,
	
	#[allow(missing_docs)]
	Kannada,
	
	#[allow(missing_docs)]
	Kashmiri,
	
	#[allow(missing_docs)]
	Kazakh,
	
	#[allow(missing_docs)]
	Konkani,
	
	#[allow(missing_docs)]
	Korean(KoreanSubLanguage),
	
	#[allow(missing_docs)]
	Latvian,
	
	#[allow(missing_docs)]
	Lithuanian(LithuanianSubLanguage),
	
	#[allow(missing_docs)]
	Macedonian,
	
	#[allow(missing_docs)]
	Malay(MalaySubLanguage),
	
	#[allow(missing_docs)]
	Malayalam,
	
	#[allow(missing_docs)]
	Manipuri,
	
	#[allow(missing_docs)]
	Marathi,
	
	#[allow(missing_docs)]
	Nepali,
	
	#[allow(missing_docs)]
	Norwegian(NorwegianSubLanguage),
	
	#[allow(missing_docs)]
	Oriya,
	
	#[allow(missing_docs)]
	Polish,
	
	#[allow(missing_docs)]
	Portuguese(PortugueseSubLanguage),
	
	#[allow(missing_docs)]
	Punjabi,
	
	#[allow(missing_docs)]
	Romanian,
	
	#[allow(missing_docs)]
	Russian,
	
	#[allow(missing_docs)]
	Sanskrit,
	
	#[allow(missing_docs)]
	Serbian(CyrillicOrLatinSubLanguage),
	
	#[allow(missing_docs)]
	Sindhi,
	
	#[allow(missing_docs)]
	Slovak,
	
	#[allow(missing_docs)]
	Slovenian,
	
	#[allow(missing_docs)]
	Spanish(SpanishSubLanguage),
	
	#[allow(missing_docs)]
	Sutu,
	
	#[allow(missing_docs)]
	Swahili,
	
	#[allow(missing_docs)]
	Swedish(SwedishSubLanguage),
	
	#[allow(missing_docs)]
	Tamil,
	
	#[allow(missing_docs)]
	Tatar,
	
	#[allow(missing_docs)]
	Telugu,
	
	#[allow(missing_docs)]
	Thai,
	
	#[allow(missing_docs)]
	Turkish,
	
	#[allow(missing_docs)]
	Ukrainian,
	
	#[allow(missing_docs)]
	Urdu(UrduSubLanguage),
	
	#[allow(missing_docs)]
	Uzbek(CyrillicOrLatinSubLanguage),
	
	#[allow(missing_docs)]
	Vietnamese,
	
	/// Human Interface Device (HID).
	HumanInterfaceDevice(HumanInterfaceDeviceSubLanguage),
	
	#[allow(missing_docs)]
	Unknown(u16)
}

impl Language
{
	#[inline(always)]
	pub(super) fn parse(language_identifier: LanguageIdentifier) -> Self
	{
		const PRIMARY_LANGUAGE_MASK: u16 = 0x03FF;
		const SUB_LANGUAGE_MASK: u16 = 0xFC00;
		
		use self::Language::*;
		
		let sub_language_code = language_identifier & SUB_LANGUAGE_MASK;
		match language_identifier & PRIMARY_LANGUAGE_MASK
		{
			0x0036 => Afrikaans,
			
			0x001C => Albanian,
			
			0x0001 => Arabic(match sub_language_code
			{
				0x0400 => ArabicSubLanguage::SaudiArabia,
				
				0x0800 => ArabicSubLanguage::Iraq,
				
				0x0C00 => ArabicSubLanguage::Egypt,
				
				0x1000 => ArabicSubLanguage::Libya,
				
				0x1400 => ArabicSubLanguage::Algeria,
				
				0x1800 => ArabicSubLanguage::Morocco,
				
				0x1C00 => ArabicSubLanguage::Tunisia,
				
				0x2000 => ArabicSubLanguage::Oman,
				
				0x2400 => ArabicSubLanguage::Yemen,
				
				0x2800 => ArabicSubLanguage::Syria,
				
				0x2C00 => ArabicSubLanguage::Jordan,
				
				0x3000 => ArabicSubLanguage::Lebanon,
				
				0x3400 => ArabicSubLanguage::Kuwait,
				
				0x3800 => ArabicSubLanguage::UnitedArabEmirates,
				
				0x3C00 => ArabicSubLanguage::Bahrain,
				
				0x4000 => ArabicSubLanguage::Qatar,
				
				_ => ArabicSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x002B => Armenian,
			
			0x004D => Assamese,
			
			0x002C => Azeri(match sub_language_code
			{
				0x0400 => CyrillicOrLatinSubLanguage::Latin,
				
				0x0800 => CyrillicOrLatinSubLanguage::Cyrillic,
				
				_ => CyrillicOrLatinSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x002D => Basque,
			
			0x0023 => Belarussian,
			
			0x0045 => Bengali,
			
			0x0002 => Bulgarian,
			
			0x0055 => Burmese,
			
			0x0003 => Catalan,
			
			0x0004 => Chinese(match sub_language_code
			{
				0x0400 => ChineseSubLanguage::Taiwan,
				
				0x0800 => ChineseSubLanguage::China,
				
				0x0C00 => ChineseSubLanguage::HongKong,
				
				0x1000 => ChineseSubLanguage::Singapore,
				
				0x1400 => ChineseSubLanguage::Macau,
				
				_ => ChineseSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x001A => match sub_language_code
			{
				0x0400 => Croatian,
				
				0x0C00 => Serbian(CyrillicOrLatinSubLanguage::Cyrillic),
				
				0x0800 => Serbian(CyrillicOrLatinSubLanguage::Latin),
				
				_ => Serbian(CyrillicOrLatinSubLanguage::Unknown((sub_language_code >> 10) as u6)),
			},
			
			0x0005 => Czech,
			
			0x0006 => Danish,
			
			0x0013 => Dutch(match sub_language_code
			{
				0x0400 => DutchSubLanguage::Netherlands,
				
				0x0800 => DutchSubLanguage::Belgium,
				
				_ => DutchSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x0009 => English(match sub_language_code
			{
				0x0400 => EnglishSubLanguage::UnitedStates,
				
				0x0800 => EnglishSubLanguage::UnitedKingdom,
				
				0x0C00 => EnglishSubLanguage::Australia,
				
				0x1000 => EnglishSubLanguage::Canada,
				
				0x1400 => EnglishSubLanguage::NewZealand,
				
				0x1800 => EnglishSubLanguage::Ireland,
				
				0x1C00 => EnglishSubLanguage::SouthAfrica,
				
				0x2000 => EnglishSubLanguage::Jamaica,
				
				0x2400 => EnglishSubLanguage::Caribbean,
				
				0x2800 => EnglishSubLanguage::Belize,
				
				0x2C00 => EnglishSubLanguage::Trinidad,
				
				0x3000 => EnglishSubLanguage::Zimbabwe,
				
				0x3400 => EnglishSubLanguage::Philippines,
				
				_ => EnglishSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x0025 => Estonian,
			
			0x0038 => Faeroese,
			
			0x0029 => Farsi,
			
			0x000B => Finnish,
			
			0x000C => French(match sub_language_code
			{
				0x0400 => FrenchSubLanguage::Standard,
				
				0x0800 => FrenchSubLanguage::Belgium,
				
				0x0C00 => FrenchSubLanguage::Canada,
				
				0x1000 => FrenchSubLanguage::Switzerland,
				
				0x1400 => FrenchSubLanguage::Luxembourg,
				
				0x1800 => FrenchSubLanguage::Monaco,
				
				_ => FrenchSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x0037 => Georgian,
			
			0x0007 => German(match sub_language_code
			{
				0x0400 => GermanSubLanguage::Standard,
				
				0x0800 => GermanSubLanguage::Switzerland,
				
				0x0C00 => GermanSubLanguage::Austria,
				
				0x1000 => GermanSubLanguage::Luxembourg,
				
				0x1400 => GermanSubLanguage::Liechtenstein,
				
				_ => GermanSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x0008 => Greek,
			
			0x0047 => Gujarati,
			
			0x000D => Hebrew,
			
			0x0039 => Hindi,
			
			0x000E => Hungarian,
			
			0x000F => Icelandic,
			
			0x0021 => Indonesian,
			
			0x0010 => Italian(match sub_language_code
			{
				0x0400 => ItalianSubLanguage::Standard,
				
				0x0800 => ItalianSubLanguage::Switzerland,
				
				_ => ItalianSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x0011 => Japanese,
			
			0x004B => Kannada,
			
			0x0060 => Kashmiri,
			
			0x003F => Kazakh,
			
			0x0057 => Konkani,
			
			0x0012 => Korean(match sub_language_code
			{
				0x0400 => KoreanSubLanguage::Standard,
				
				0x0800 => KoreanSubLanguage::Johab,
				
				_ => KoreanSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x0026 => Latvian,
			
			0x0027 => Lithuanian(match sub_language_code
			{
				0x0400 => LithuanianSubLanguage::Standard,
				
				0x0800 => LithuanianSubLanguage::Classic,
				
				_ => LithuanianSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x002F => Macedonian,
			
			0x003E => Malay(match sub_language_code
			{
				0x0400 => MalaySubLanguage::Malaysia,
				
				0x0800 => MalaySubLanguage::BruneiDarussalam,
				
				_ => MalaySubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x004C => Malayalam,
			
			0x0058 => Manipuri,
			
			0x004E => Marathi,
			
			0x0061 => Nepali,
			
			0x0014 => Norwegian( match sub_language_code
			{
				0x0400 => NorwegianSubLanguage::Bokmal,
				
				0x0800 => NorwegianSubLanguage::Nynorsk,
				
				_ => NorwegianSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x0048 => Oriya,
			
			0x0015 => Polish,
			
			0x0016 => Portuguese(match sub_language_code
			{
				0x0400 => PortugueseSubLanguage::Brazil,
				
				0x0800 => PortugueseSubLanguage::Standard,
				
				_ => PortugueseSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x0046 => Punjabi,
			
			0x0018 => Romanian,
			
			0x0019 => Russian,
			
			0x004F => Sanskrit,
			
			0x0059 => Sindhi,
			
			0x001B => Slovak,
			
			0x0024 => Slovenian,
			
			0x000A => Spanish(match sub_language_code
			{
				0x0400 => SpanishSubLanguage::Traditional,
				
				0x0800 => SpanishSubLanguage::Mexico,
				
				0x0C00 => SpanishSubLanguage::Modern,
				
				0x1000 => SpanishSubLanguage::Guatemala,
				
				0x1400 => SpanishSubLanguage::CostaRica,
				
				0x1800 => SpanishSubLanguage::Panama,
				
				0x1C00 => SpanishSubLanguage::DominicanRepublic,
				
				0x2000 => SpanishSubLanguage::Venezuela,
				
				0x2400 => SpanishSubLanguage::Colombia,
				
				0x2800 => SpanishSubLanguage::Peru,
				
				0x2C00 => SpanishSubLanguage::Argentina,
				
				0x3000 => SpanishSubLanguage::Ecuador,
				
				0x3400 => SpanishSubLanguage::Chile,
				
				0x3800 => SpanishSubLanguage::Uruguay,
				
				0x3C00 => SpanishSubLanguage::Paraguay,
				
				0x4000 => SpanishSubLanguage::Bolivia,
				
				0x4400 => SpanishSubLanguage::ElSalvador,
				
				0x4800 => SpanishSubLanguage::Honduras,
				
				0x4C00 => SpanishSubLanguage::Nicaragua,
				
				0x5000 => SpanishSubLanguage::PuertoRico,
				
				_ => SpanishSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x0030 => Sutu,
			
			0x0041 => Swahili,
			
			0x001D => Swedish(match sub_language_code
			{
				0x0400 => SwedishSubLanguage::Standard,
				
				0x0800 => SwedishSubLanguage::Finland,
				
				_ => SwedishSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x0049 => Tamil,
			
			0x0044 => Tatar,
			
			0x004A => Telugu,
			
			0x001E => Thai,
			
			0x001F => Turkish,
			
			0x0022 => Ukrainian,
			
			0x0020 => Urdu(match sub_language_code
			{
				0x0400 => UrduSubLanguage::Pakistan,
				
				0x0800 => UrduSubLanguage::India,
				
				_ => UrduSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x0043 => Uzbek(match sub_language_code
			{
				0x0400 => CyrillicOrLatinSubLanguage::Latin,
				
				0x0800 => CyrillicOrLatinSubLanguage::Cyrillic,
				
				_ => CyrillicOrLatinSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			0x002A => Vietnamese,
			
			0x00FF => HumanInterfaceDevice(match sub_language_code
			{
				0x0400 => HumanInterfaceDeviceSubLanguage::UsageDataDescriptor,
				
				0xF000 => HumanInterfaceDeviceSubLanguage::VendorDefined1,
				
				0xF400 => HumanInterfaceDeviceSubLanguage::VendorDefined2,
				
				0xF800 => HumanInterfaceDeviceSubLanguage::VendorDefined3,
				
				0xFC00 => HumanInterfaceDeviceSubLanguage::VendorDefined4,
				
				_ => HumanInterfaceDeviceSubLanguage::Unknown((sub_language_code >> 10) as u6),
			}),
			
			_ => Unknown(language_identifier),
		}
	}
}
