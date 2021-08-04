// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Language.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(AsRefStr, Display, EnumString)]
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
	Unknown(LanguageIdentifier)
}

impl Default for Language
{
	#[inline(always)]
	fn default() -> Self
	{
		Language::English(EnglishSubLanguage::default())
	}
}

impl<'de> Deserialize<'de> for Language
{
	#[inline(always)]
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>
	{
		struct OurVisitor;
		
		impl<'de> Visitor<'de> for OurVisitor
		{
			type Value = Language;
			
			#[inline(always)]
			fn expecting(&self, formatter: &mut Formatter) -> fmt::Result
			{
				write!(formatter, "A language string")
			}
			
			#[allow(unused_qualifications)]
			#[inline(always)]
			fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E>
			{
				use ArabicSubLanguage::*;
				use ChineseSubLanguage::*;
				use CyrillicOrLatinSubLanguage::*;
				use DutchSubLanguage::*;
				use EnglishSubLanguage::*;
				use FrenchSubLanguage::Monaco;
				use GermanSubLanguage::*;
				use HumanInterfaceDeviceSubLanguage::*;
				use KoreanSubLanguage::Johab;
				use LithuanianSubLanguage::Classic;
				use Language::*;
				use MalaySubLanguage::*;
				use NorwegianSubLanguage::*;
				use PortugueseSubLanguage::Brazil;
				use SpanishSubLanguage::*;
				use SwedishSubLanguage::Finland;
				use UrduSubLanguage::*;
				let language = match v
				{
					"Afrikaans" => Afrikaans,
					
					"Albanian" => Albanian,
					
					"Arabic-SaudiArabia" => Arabic(SaudiArabia),
					"Arabic-Iraq" => Arabic(Iraq),
					"Arabic-Egypt" => Arabic(Egypt),
					"Arabic-Libya" => Arabic(Libya),
					"Arabic-Algeria" => Arabic(Algeria),
					"Arabic-Morocco" => Arabic(Morocco),
					"Arabic-Tunisia" => Arabic(Tunisia),
					"Arabic-Oman" => Arabic(Oman),
					"Arabic-Yemen" => Arabic(Yemen),
					"Arabic-Syria" => Arabic(Syria),
					"Arabic-Jordan" => Arabic(Jordan),
					"Arabic-Lebanon" => Arabic(Lebanon),
					"Arabic-Kuwait" => Arabic(Kuwait),
					"Arabic-UnitedArabEmirates" => Arabic(UnitedArabEmirates),
					"Arabic-Bahrain" => Arabic(Bahrain),
					"Arabic-Qatar" => Arabic(Qatar),
					
					"Armenian" => Armenian,
					
					"Assamese" => Assamese,
					
					"Azeri-Cyrillic" => Azeri(Cyrillic),
					"Azeri-Latin" => Azeri(Latin),
					
					"Basque" => Basque,
					
					"Belarussian" => Belarussian,
					
					"Bengali" => Bengali,
					
					"Bulgarian" => Bulgarian,
					
					"Burmese" => Burmese,
					
					"Catalan" => Catalan,
					
					"Chinese-Taiwan" => Chinese(Taiwan),
					"Chinese-China" => Chinese(China),
					"Chinese-HongKong" => Chinese(HongKong),
					"Chinese-Singapore" => Chinese(Singapore),
					"Chinese-Macau" => Chinese(Macau),
					
					"Croatian" => Croatian,
					
					"Czech" => Czech,
					
					"Danish" => Danish,
					
					"Dutch-Netherlands" => Dutch(Netherlands),
					"Dutch-Belgium" => Dutch(DutchSubLanguage::Belgium),
					
					"English-UnitedStates" => English(UnitedStates),
					"English-UnitedKingdom" => English(UnitedKingdom),
					"English-Australia" => English(Australia),
					"English-Canada" => English(EnglishSubLanguage::Canada),
					"English-NewZealand" => English(NewZealand),
					"English-Ireland" => English(Ireland),
					"English-SouthAfrica" => English(SouthAfrica),
					"English-Jamaica" => English(Jamaica),
					"English-Caribbean" => English(Caribbean),
					"English-Belize" => English(Belize),
					"English-Trinidad" => English(Trinidad),
					"English-Zimbabwe" => English(Zimbabwe),
					"English-Philippines" => English(Philippines),
					
					"Estonian" => Estonian,
					
					"Faeroese" => Faeroese,
					
					"Farsi" => Farsi,
					
					"French-Standard" => French(FrenchSubLanguage::Standard),
					"French-Belgium" => French(FrenchSubLanguage::Belgium),
					"French-Canada" => French(FrenchSubLanguage::Canada),
					"French-Switzerland" => French(FrenchSubLanguage::Switzerland),
					"French-Luxembourg" => French(FrenchSubLanguage::Luxembourg),
					"French-Monaco" => French(Monaco),
					
					"Finnish" => Finnish,
					
					"Georgian" => Georgian,
					
					"German-Standard" => German(GermanSubLanguage::Standard),
					"German-Switzerland" => German(GermanSubLanguage::Switzerland),
					"German-Austria" => German(Austria),
					"German-Luxembourg" => German(GermanSubLanguage::Luxembourg),
					"German-Liechtenstein" => German(Liechtenstein),
					
					"Greek" => Greek,
					
					"Gujarati" => Gujarati,
					
					"Hebrew" => Hebrew,
					
					"Hindi" => Hindi,
					
					"Hungarian" => Hungarian,
					
					"Icelandic" => Icelandic,
					
					"Indonesian" => Indonesian,
					
					"Italian-Standard" => Italian(ItalianSubLanguage::Standard),
					"Italian-Switzerland" => Italian(ItalianSubLanguage::Switzerland),
					
					"Japanese" => Japanese,
					
					"Kannada" => Kannada,
					
					"Kashmiri" => Kashmiri,
					
					"Kazakh" => Kazakh,
					
					"Konkani" => Konkani,
					
					"Korean-Standard" => Korean(KoreanSubLanguage::Standard),
					"Korean-Johab" => Korean(Johab),
					
					"Latvian" => Latvian,
					
					"Lithuanian-Standard" => Lithuanian(LithuanianSubLanguage::Standard),
					"Lithuanian-Classic" => Lithuanian(Classic),
					
					"Macedonian" => Macedonian,
					
					"Malay-Malaysia" => Malay(Malaysia),
					"Malay-BruneiDarussalam" => Malay(BruneiDarussalam),
					
					"Malayalam" => Malayalam,
					
					"Manipuri" => Manipuri,
					
					"Marathi" => Marathi,
					
					"Nepali" => Nepali,
					
					"Norwegian-Bokmål" => Norwegian(Bokmål),
					"Norwegian-Nynorsk" => Norwegian(Nynorsk),
					
					"Oriya" => Oriya,
					
					"Polish" => Polish,
					
					"Portuguese-Brazil" => Portuguese(Brazil),
					"Portuguese-Standard" => Portuguese(PortugueseSubLanguage::Standard),
					
					"Punjabi" => Punjabi,
					
					"Romanian" => Romanian,
					
					"Russian" => Russian,
					
					"Sanskrit" => Sanskrit,
					
					"Serbian-Cyrillic" => Serbian(Cyrillic),
					"Serbian-Latin" => Serbian(Cyrillic),
					
					"Sindhi" => Sindhi,
					
					"Slovak" => Slovak,
					
					"Slovenian" => Slovenian,
					
					"Spanish-Traditional" => Spanish(Traditional),
					"Spanish-Mexico" => Spanish(Mexico),
					"Spanish-Modern" => Spanish(Modern),
					"Spanish-Guatemala" => Spanish(Guatemala),
					"Spanish-CostaRica" => Spanish(CostaRica),
					"Spanish-Panama" => Spanish(Panama),
					"Spanish-DominicanRepublic" => Spanish(DominicanRepublic),
					"Spanish-Venezuela" => Spanish(Venezuela),
					"Spanish-Colombia" => Spanish(Colombia),
					"Spanish-Peru" => Spanish(Peru),
					"Spanish-Argentina" => Spanish(Argentina),
					"Spanish-Ecuador" => Spanish(Ecuador),
					"Spanish-Chile" => Spanish(Chile),
					"Spanish-Uruguay" => Spanish(Uruguay),
					"Spanish-Paraguay" => Spanish(Paraguay),
					"Spanish-Bolivia" => Spanish(Bolivia),
					"Spanish-ElSalvador" => Spanish(ElSalvador),
					"Spanish-Honduras" => Spanish(Honduras),
					"Spanish-Nicaragua" => Spanish(Nicaragua),
					"Spanish-PuertoRico" => Spanish(PuertoRico),
					
					"Sutu" => Sutu,
					
					"Swahili" => Swahili,
					
					"Swedish-Standard" => Swedish(SwedishSubLanguage::Standard),
					"Swedish-Classic" => Swedish(Finland),
					
					"Tamil" => Tamil,
					
					"Tatar" => Tatar,
					
					"Telugu" => Telugu,
					
					"Thai" => Thai,
					
					"Turkish" => Turkish,
					
					"Urdu-Pakistan" => Urdu(Pakistan),
					"Urdu-India" => Urdu(India),
					
					"Ukrainian" => Ukrainian,
					
					"Uzbek-Cyrillic" => Uzbek(Cyrillic),
					"Uzbek-Latin" => Uzbek(Latin),
					
					"Vietnamese" => Vietnamese,
					
					"HumanInterfaceDevice-UsageDataDescriptor" => HumanInterfaceDevice(UsageDataDescriptor),
					"HumanInterfaceDevice-VendorDefined1" => HumanInterfaceDevice(VendorDefined1),
					"HumanInterfaceDevice-VendorDefined2" => HumanInterfaceDevice(VendorDefined2),
					"HumanInterfaceDevice-VendorDefined3" => HumanInterfaceDevice(VendorDefined3),
					"HumanInterfaceDevice-VendorDefined4" => HumanInterfaceDevice(VendorDefined4),
					
					_ => match v.split_once('-')
					{
						Some(("Unknown", after)) => match u16::from_str(after)
						{
							Ok(language_identifier) => Language::parse(language_identifier),
							
							Err(error) => return Err(E::custom(error)),
						},
						
						None => return Err(E::custom("Does not contain a hyphen")),
						
						_ => return Err(E::custom("Does not start with Unknown-"))
					}
				};
				
				Ok(language)
			}
		}
		
		deserializer.deserialize_str(OurVisitor)
	}
}

impl Serialize for Language
{
	#[inline(always)]
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>
	{
		let string = self.to_string();
		serializer.serialize_str(string.borrow())
	}
}

impl Language
{
	#[inline(always)]
	fn to_string(&self) -> Cow<str>
	{
		use Cow::*;
		use Language::*;
		
		match self
		{
			Arabic(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			Azeri(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			Chinese(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			Dutch(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			English(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			French(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			German(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			Italian(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			Korean(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			Lithuanian(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			Norwegian(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			Portuguese(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			Serbian(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			Spanish(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			Urdu(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			Uzbek(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			HumanInterfaceDevice(sub_language) => Owned(format!("{}-{}", self.as_ref(), sub_language.as_ref())),

			Unknown(language_identifier) => Owned(format!("Unknown-{}", language_identifier)),
			
			_ => Borrowed(self.as_ref()),
		}
	}
	
	#[inline(always)]
	pub(super) fn parse(language_identifier: LanguageIdentifier) -> Self
	{
		const PRIMARY_LANGUAGE_MASK: u16 = 0x03FF;
		const SUB_LANGUAGE_MASK: u16 = 0xFC00;
		
		use Language::*;
		
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
				
				_ => return Unknown(language_identifier),
			}),
			
			0x002B => Armenian,
			
			0x004D => Assamese,
			
			0x002C => Azeri(match sub_language_code
			{
				0x0400 => CyrillicOrLatinSubLanguage::Latin,
				
				0x0800 => CyrillicOrLatinSubLanguage::Cyrillic,
				
				_ => return Unknown(language_identifier),
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
				
				_ => return Unknown(language_identifier),
			}),
			
			0x001A => match sub_language_code
			{
				0x0400 => Croatian,
				
				0x0C00 => Serbian(CyrillicOrLatinSubLanguage::Cyrillic),
				
				0x0800 => Serbian(CyrillicOrLatinSubLanguage::Latin),
				
				_ => return Unknown(language_identifier),
			},
			
			0x0005 => Czech,
			
			0x0006 => Danish,
			
			0x0013 => Dutch(match sub_language_code
			{
				0x0400 => DutchSubLanguage::Netherlands,
				
				0x0800 => DutchSubLanguage::Belgium,
				
				_ => return Unknown(language_identifier),
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
				
				_ => return Unknown(language_identifier),
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
				
				_ => return Unknown(language_identifier),
			}),
			
			0x0037 => Georgian,
			
			0x0007 => German(match sub_language_code
			{
				0x0400 => GermanSubLanguage::Standard,
				
				0x0800 => GermanSubLanguage::Switzerland,
				
				0x0C00 => GermanSubLanguage::Austria,
				
				0x1000 => GermanSubLanguage::Luxembourg,
				
				0x1400 => GermanSubLanguage::Liechtenstein,
				
				_ => return Unknown(language_identifier),
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
				
				_ => return Unknown(language_identifier),
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
				
				_ => return Unknown(language_identifier),
			}),
			
			0x0026 => Latvian,
			
			0x0027 => Lithuanian(match sub_language_code
			{
				0x0400 => LithuanianSubLanguage::Standard,
				
				0x0800 => LithuanianSubLanguage::Classic,
				
				_ => return Unknown(language_identifier),
			}),
			
			0x002F => Macedonian,
			
			0x003E => Malay(match sub_language_code
			{
				0x0400 => MalaySubLanguage::Malaysia,
				
				0x0800 => MalaySubLanguage::BruneiDarussalam,
				
				_ => return Unknown(language_identifier),
			}),
			
			0x004C => Malayalam,
			
			0x0058 => Manipuri,
			
			0x004E => Marathi,
			
			0x0061 => Nepali,
			
			0x0014 => Norwegian( match sub_language_code
			{
				0x0400 => NorwegianSubLanguage::Bokmål,
				
				0x0800 => NorwegianSubLanguage::Nynorsk,
				
				_ => return Unknown(language_identifier),
			}),
			
			0x0048 => Oriya,
			
			0x0015 => Polish,
			
			0x0016 => Portuguese(match sub_language_code
			{
				0x0400 => PortugueseSubLanguage::Brazil,
				
				0x0800 => PortugueseSubLanguage::Standard,
				
				_ => return Unknown(language_identifier),
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
				
				_ => return Unknown(language_identifier),
			}),
			
			0x0030 => Sutu,
			
			0x0041 => Swahili,
			
			0x001D => Swedish(match sub_language_code
			{
				0x0400 => SwedishSubLanguage::Standard,
				
				0x0800 => SwedishSubLanguage::Finland,
				
				_ => return Unknown(language_identifier),
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
				
				_ => return Unknown(language_identifier),
			}),
			
			0x0043 => Uzbek(match sub_language_code
			{
				0x0400 => CyrillicOrLatinSubLanguage::Latin,
				
				0x0800 => CyrillicOrLatinSubLanguage::Cyrillic,
				
				_ => return Unknown(language_identifier),
			}),
			
			0x002A => Vietnamese,
			
			0x00FF => HumanInterfaceDevice(match sub_language_code
			{
				0x0400 => HumanInterfaceDeviceSubLanguage::UsageDataDescriptor,
				
				0xF000 => HumanInterfaceDeviceSubLanguage::VendorDefined1,
				
				0xF400 => HumanInterfaceDeviceSubLanguage::VendorDefined2,
				
				0xF800 => HumanInterfaceDeviceSubLanguage::VendorDefined3,
				
				0xFC00 => HumanInterfaceDeviceSubLanguage::VendorDefined4,
				
				_ => return Unknown(language_identifier),
			}),
			
			_ => Unknown(language_identifier),
		}
	}
}
