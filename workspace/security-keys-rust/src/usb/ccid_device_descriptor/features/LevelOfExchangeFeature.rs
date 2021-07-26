// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum LevelOfExchangeFeature
{
	CharacterLevelExchange = 0x0000_0000,

	TpduLevelExchangeWithCcid = 0x0001_0000,
	
	ShortApduLevelExchangeWithCcid = 0x0002_0000,
	
	ShortAndExtendedApduLevelExchangeWithCcid = 0x0004_0000,
}

impl LevelOfExchangeFeature
{
	#[inline(always)]
	fn parse(dwFeatures: u32) -> Result<Self, &'static str>
	{
		const TpduLevelExchangeWithCcid: u32 = LevelOfExchangeFeature::TpduLevelExchangeWithCcid as u32;
		const ShortApduLevelExchangeWithCcid: u32 = LevelOfExchangeFeature::ShortApduLevelExchangeWithCcid as u32;
		const ShortAndExtendedApduLevelExchangeWithCcid: u32 = LevelOfExchangeFeature::ShortAndExtendedApduLevelExchangeWithCcid as u32;
		const Mask: u32 = TpduLevelExchangeWithCcid | ShortApduLevelExchangeWithCcid | ShortAndExtendedApduLevelExchangeWithCcid;
		
		match dwFeatures & Mask
		{
			0 => Ok(LevelOfExchangeFeature::CharacterLevelExchange),
			
			TpduLevelExchangeWithCcid => Ok(LevelOfExchangeFeature::TpduLevelExchangeWithCcid),
			
			ShortApduLevelExchangeWithCcid => Ok(LevelOfExchangeFeature::ShortApduLevelExchangeWithCcid),
			
			ShortAndExtendedApduLevelExchangeWithCcid => Ok(LevelOfExchangeFeature::ShortAndExtendedApduLevelExchangeWithCcid),
			
			_ => Err("Invalid LevelOfExchangeFeature; can not have more than one of TpduLevelExchangeWithCcid, ShortApduLevelExchangeWithCcid or ShortAndExtendedApduLevelExchangeWithCcid"),
		}
	}
	#[inline(always)]
	fn is_apdu_level(self) -> bool
	{
		use self::LevelOfExchangeFeature::*;
		
		self == ShortApduLevelExchangeWithCcid || self == ShortAndExtendedApduLevelExchangeWithCcid
	}
}
