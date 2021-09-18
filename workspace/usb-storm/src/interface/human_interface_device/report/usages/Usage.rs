// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Usage.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Usage
{
	#[allow(missing_docs)]
	GenericDesktop(UsageIdentifier),

	#[allow(missing_docs)]
	SimulationControls(UsageIdentifier),

	#[allow(missing_docs)]
	VirtualRealityControls(VirtualRealityControlsUsage),

	#[allow(missing_docs)]
	SportsControls(UsageIdentifier),

	#[allow(missing_docs)]
	GameControls(UsageIdentifier),

	#[allow(missing_docs)]
	GenericDeviceControls(UsageIdentifier),

	#[allow(missing_docs)]
	KeyboardOrKeypad(UsageIdentifier),

	#[allow(missing_docs)]
	LightEmittingDiode(UsageIdentifier),

	#[allow(missing_docs)]
	Button(ButtonUsage),

	#[allow(missing_docs)]
	Ordinal(OrdinalUsage),

	#[allow(missing_docs)]
	TelephonyDevice(UsageIdentifier),

	#[allow(missing_docs)]
	Consumer(UsageIdentifier),

	#[allow(missing_docs)]
	Digitizers(UsageIdentifier),

	#[allow(missing_docs)]
	Haptics(UsageIdentifier),

	#[allow(missing_docs)]
	PhysicalInterfaceDevice(UsageIdentifier),

	#[allow(missing_docs)]
	Unicode(Ucs2CodePoint),

	#[allow(missing_docs)]
	EyeAndHeadTrackers(UsageIdentifier),

	#[allow(missing_docs)]
	AuxillaryDisplay(UsageIdentifier),

	#[allow(missing_docs)]
	Sensors(UsageIdentifier),

	#[allow(missing_docs)]
	MedicalInstrument(UsageIdentifier),

	#[allow(missing_docs)]
	BrailleDisplay(UsageIdentifier),

	#[allow(missing_docs)]
	LightingAndIllumination(UsageIdentifier),

	#[allow(missing_docs)]
	Monitor0(UsageIdentifier),

	#[allow(missing_docs)]
	Monitor1(UsageIdentifier),

	#[allow(missing_docs)]
	Monitor2(UsageIdentifier),

	#[allow(missing_docs)]
	Monitor3(UsageIdentifier),

	#[allow(missing_docs)]
	Power0(UsageIdentifier),

	#[allow(missing_docs)]
	Power1(UsageIdentifier),

	#[allow(missing_docs)]
	Power2(UsageIdentifier),

	#[allow(missing_docs)]
	Power3(UsageIdentifier),
	
	#[allow(missing_docs)]
	PointOfSaleBarCodeScanner(UsageIdentifier),
	
	#[allow(missing_docs)]
	PointOfSaleScale(UsageIdentifier),
	
	#[allow(missing_docs)]
	PointOfSaleMagneticStripeReading(UsageIdentifier),
	
	#[allow(missing_docs)]
	PointOfSaleReserved(UsageIdentifier),
	
	#[allow(missing_docs)]
	CameraControl(CameraControlUsage),
	
	#[allow(missing_docs)]
	Arcade(UsageIdentifier),

	#[allow(missing_docs)]
	GamingDevice(UsageIdentifier),

	#[allow(missing_docs)]
	FidoAlliance(FidoAllianceUsage),

	#[allow(missing_docs)]
	Reserved
	{
		reserved_page: NonZeroU16,

		identifier: UsageIdentifier,
	},
	
	#[allow(missing_docs)]
	VendorDefined
	{
		page_code: u8,
	
		identifier: UsageIdentifier,
	}
}

impl Usage
{
	#[inline(always)]
	pub(super) fn from_usage_page(usage_page: ParsingUsagePage, identifier: UsageIdentifier) -> Usage
	{
		use ParsingUsagePage::*;
		
		match usage_page
		{
			GenericDesktop => Usage::GenericDesktop(identifier),
			
			SimulationControls => Usage::SimulationControls(identifier),
			
			VirtualRealityControls => Usage::VirtualRealityControls(VirtualRealityControlsUsage::from(identifier)),
			
			SportsControls => Usage::SportsControls(identifier),
			
			GameControls => Usage::GameControls(identifier),
			
			GenericDeviceControls => Usage::GenericDeviceControls(identifier),
			
			KeyboardOrKeypad => Usage::KeyboardOrKeypad(identifier),
			
			LightEmittingDiode => Usage::LightEmittingDiode(identifier),
			
			Button => Usage::Button(ButtonUsage::from(identifier)),
			
			Ordinal => Usage::Ordinal(OrdinalUsage::from(identifier)),
			
			TelephonyDevice => Usage::TelephonyDevice(identifier),
			
			Consumer => Usage::Consumer(identifier),
			
			Digitizers => Usage::Digitizers(identifier),
			
			Haptics => Usage::Haptics(identifier),
			
			PhysicalInterfaceDevice => Usage::PhysicalInterfaceDevice(identifier),
			
			Unicode => Usage::Unicode(Ucs2CodePoint::from(identifier)),
			
			EyeAndHeadTrackers => Usage::EyeAndHeadTrackers(identifier),
			
			AuxillaryDisplay => Usage::AuxillaryDisplay(identifier),
			
			Sensors => Usage::Sensors(identifier),
			
			MedicalInstrument => Usage::MedicalInstrument(identifier),
			
			BrailleDisplay => Usage::BrailleDisplay(identifier),
			
			LightingAndIllumination => Usage::LightingAndIllumination(identifier),
			
			Monitor0 => Usage::Monitor0(identifier),
			
			Monitor1 => Usage::Monitor1(identifier),
			
			Monitor2 => Usage::Monitor2(identifier),
			
			Monitor3 => Usage::Monitor3(identifier),
			
			Power0 => Usage::Monitor0(identifier),
			
			Power1 => Usage::Monitor1(identifier),
			
			Power2 => Usage::Monitor2(identifier),
			
			Power3 => Usage::Monitor3(identifier),
			
			PointOfSaleBarCodeScanner => Usage::PointOfSaleBarCodeScanner(identifier),
			
			PointOfSaleScale => Usage::PointOfSaleScale(identifier),
			
			PointOfSaleMagneticStripeReading => Usage::PointOfSaleMagneticStripeReading(identifier),
			
			PointOfSaleReserved => Usage::PointOfSaleReserved(identifier),
			
			CameraControl => Usage::CameraControl(CameraControlUsage::from(identifier)),
			
			Arcade => Usage::Arcade(identifier),
			
			GamingDevice => Usage::GamingDevice(identifier),
			
			FidoAlliance => Usage::FidoAlliance(FidoAllianceUsage::from(identifier)),

			Reserved(reserved_page) => Usage::Reserved
			{
				reserved_page,
				
				identifier,
			},
			
			VendorDefined(page_code) => Usage::VendorDefined
			{
				page_code,
				
				identifier,
			},
		}
	}
}
