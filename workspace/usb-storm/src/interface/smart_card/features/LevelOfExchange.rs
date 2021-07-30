// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Level of exchange; modern smart cards should be using `ShortAndExtendedApduLevelExchangeWithCcid`.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum LevelOfExchange
{
	#[allow(missing_docs)]
	CharacterLevelExchange = 0x0000_0000,
	
	#[allow(missing_docs)]
	TpduLevelExchangeWithCcid = 0x0001_0000,
	
	#[allow(missing_docs)]
	ShortApduLevelExchangeWithCcid = 0x0002_0000,
	
	#[allow(missing_docs)]
	ShortAndExtendedApduLevelExchangeWithCcid = 0x0004_0000,
}

impl LevelOfExchange
{
	#[inline(always)]
	fn parse(dwFeatures: u32) -> Result<Self, FeaturesParseError>
	{
		const TpduLevelExchangeWithCcid: u32 = LevelOfExchange::TpduLevelExchangeWithCcid as u32;
		const ShortApduLevelExchangeWithCcid: u32 = LevelOfExchange::ShortApduLevelExchangeWithCcid as u32;
		const ShortAndExtendedApduLevelExchangeWithCcid: u32 = LevelOfExchange::ShortAndExtendedApduLevelExchangeWithCcid as u32;
		const Mask: u32 = TpduLevelExchangeWithCcid | ShortApduLevelExchangeWithCcid | ShortAndExtendedApduLevelExchangeWithCcid;
		
		match dwFeatures & Mask
		{
			0 => Ok(LevelOfExchange::CharacterLevelExchange),
			
			TpduLevelExchangeWithCcid => Ok(LevelOfExchange::TpduLevelExchangeWithCcid),
			
			ShortApduLevelExchangeWithCcid => Ok(LevelOfExchange::ShortApduLevelExchangeWithCcid),
			
			ShortAndExtendedApduLevelExchangeWithCcid => Ok(LevelOfExchange::ShortAndExtendedApduLevelExchangeWithCcid),
			
			_ => Err(FeaturesParseError::InvalidLevelOfExchangeFeature),
		}
	}
	
	/// Is the level of exchange APDU?
	#[inline(always)]
	pub fn is_apdu_level(self) -> bool
	{
		use LevelOfExchange::*;
		
		self == ShortApduLevelExchangeWithCcid || self.is_extended_apdu_level()
	}
	
	/// Is the level of exchange extended APDU?
	#[inline(always)]
	pub fn is_extended_apdu_level(self) -> bool
	{
		use LevelOfExchange::*;
		
		self == ShortAndExtendedApduLevelExchangeWithCcid
	}
}
