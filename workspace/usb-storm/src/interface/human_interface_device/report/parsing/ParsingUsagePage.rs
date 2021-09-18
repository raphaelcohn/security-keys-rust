// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(super) enum ParsingUsagePage
{
	#[allow(missing_docs)]
	GenericDesktop,
	
	#[allow(missing_docs)]
	SimulationControls,
	
	#[allow(missing_docs)]
	VirtualRealityControls,
	
	#[allow(missing_docs)]
	SportsControls,
	
	#[allow(missing_docs)]
	GameControls,
	
	#[allow(missing_docs)]
	GenericDeviceControls,
	
	#[allow(missing_docs)]
	KeyboardOrKeypad,
	
	#[allow(missing_docs)]
	LightEmittingDiode,
	
	#[allow(missing_docs)]
	Button,
	
	#[allow(missing_docs)]
	Ordinal,
	
	#[allow(missing_docs)]
	TelephonyDevice,
	
	#[allow(missing_docs)]
	Consumer,
	
	#[allow(missing_docs)]
	Digitizers,
	
	#[allow(missing_docs)]
	Haptics,
	
	#[allow(missing_docs)]
	PhysicalInterfaceDevice,
	
	#[allow(missing_docs)]
	Unicode,
	
	#[allow(missing_docs)]
	EyeAndHeadTrackers,
	
	#[allow(missing_docs)]
	AuxillaryDisplay,
	
	#[allow(missing_docs)]
	Sensors,
	
	#[allow(missing_docs)]
	MedicalInstrument,
	
	#[allow(missing_docs)]
	BrailleDisplay,
	
	#[allow(missing_docs)]
	LightingAndIllumination,
	
	#[allow(missing_docs)]
	Monitor0,
	
	#[allow(missing_docs)]
	Monitor1,
	
	#[allow(missing_docs)]
	Monitor2,
	
	#[allow(missing_docs)]
	Monitor3,
	
	#[allow(missing_docs)]
	Power0,
	
	#[allow(missing_docs)]
	Power1,
	
	#[allow(missing_docs)]
	Power2,
	
	#[allow(missing_docs)]
	Power3,
	
	#[allow(missing_docs)]
	PointOfSaleBarCodeScanner,
	
	#[allow(missing_docs)]
	PointOfSaleScale,
	
	#[allow(missing_docs)]
	PointOfSaleMagneticStripeReading,
	
	#[allow(missing_docs)]
	PointOfSaleReserved,
	
	#[allow(missing_docs)]
	CameraControl,
	
	#[allow(missing_docs)]
	Arcade,
	
	#[allow(missing_docs)]
	GamingDevice,
	
	#[allow(missing_docs)]
	FidoAlliance,
	
	#[allow(missing_docs)]
	Reserved(NonZeroU16),
	
	#[allow(missing_docs)]
	VendorDefined(u8),
}

impl TryFrom<u32> for ParsingUsagePage
{
	type Error = UsagePageParseError;
	
	#[inline(always)]
	fn try_from(data: u32) -> Result<Self, Self::Error>
	{
		use UsagePageParseError::*;
		
		if unlikely!(data > (u16::MAX as u32))
		{
			return Err(UsagePageTooBig { data })
		}
		Self::new_checked(data as u16, UsagePageCanNotBeZero)
	}
}

impl ParsingUsagePage
{
	#[inline(always)]
	pub(super) fn new_checked<E: error::Error>(raw_usage_page: u16, usage_page_can_not_be_zero_error: E) -> Result<Self, E>
	{
		use ParsingUsagePage::*;
		
		#[inline(always)]
		const fn reserved(value: u16) -> ParsingUsagePage
		{
			Reserved(new_non_zero_u16(value))
		}
		
		let this = match raw_usage_page
		{
			0 => return Err(usage_page_can_not_be_zero_error),
			
			0x01 => GenericDesktop,
			
			0x02 => SimulationControls,
			
			0x03 => VirtualRealityControls,
			
			0x04 => SportsControls,
			
			0x05 => GameControls,
			
			0x06 => GenericDeviceControls,
			
			0x07 => KeyboardOrKeypad,
			
			0x08 => LightEmittingDiode,
			
			0x09 => Button,
			
			0x0A => Ordinal,
			
			0x0B => TelephonyDevice,
			
			0x0C => Consumer,
			
			0x0D => Digitizers,
			
			0x0E => Haptics,
			
			0x0F => PhysicalInterfaceDevice,
			
			0x10 => Unicode,
			
			value @ 0x11 => reserved(value),
			
			0x12 => EyeAndHeadTrackers,
			
			value @ 0x13 => reserved(value),
			
			0x14 => AuxillaryDisplay,
			
			value @ 0x15 ..= 0x1F => reserved(value),
			
			0x20 => Sensors,
			
			value @ 0x21 ..= 0x3F => reserved(value),
			
			0x40 => MedicalInstrument,
			
			0x41 => BrailleDisplay,
			
			value @ 0x42 ..= 0x58 => reserved(value),
			
			0x59 => LightingAndIllumination,
			
			value @ 0x5A ..= 0x7F => reserved(value),
			
			0x80 => Monitor0,
			
			0x81 => Monitor1,
			
			0x82 => Monitor2,
			
			0x83 => Monitor3,
			
			0x84 => Power0,
			
			0x85 => Power1,
			
			0x86 => Power2,
			
			0x87 => Power3,
			
			value @ 0x88 ..= 0x8B => reserved(value),
			
			0x8C => PointOfSaleBarCodeScanner,
			
			0x8D => PointOfSaleScale,
			
			0x8E => PointOfSaleMagneticStripeReading,
			
			0x8F => PointOfSaleReserved,
			
			0x90 => CameraControl,
			
			0x91 => Arcade,
			
			0x92 => GamingDevice,
			
			value @ 0x93 ..= 0xF1CF => reserved(value),
			
			0xF1D0 => FidoAlliance,
			
			value @ 0xF1D1 ..= 0xFEFF => reserved(value),
			
			value @ _ => VendorDefined((value - 0xFF00) as u8),
		};
		
		Ok(this)
	}
	
	#[inline(always)]
	fn to_usage(self, identifier: UsageIdentifier) -> Usage
	{
		Usage::from_usage_page(self, identifier)
	}
}
