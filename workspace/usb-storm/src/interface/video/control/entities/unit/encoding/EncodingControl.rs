// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// An encoding control.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[bitflags]
#[repr(u32)]
pub enum EncodingControl
{
	#[allow(missing_docs)]
	SelectLayer = 1 << 0,
	
	#[allow(missing_docs)]
	ProfileAndToolset = 1 << 1,
	
	#[allow(missing_docs)]
	VideoResolution = 1 << 2,
	
	#[allow(missing_docs)]
	MinimumFrameInterval = 1 << 3,
	
	#[allow(missing_docs)]
	SliceMode = 1 << 4,
	
	#[allow(missing_docs)]
	RateControlMode = 1 << 5,
	
	#[allow(missing_docs)]
	AverageBitRate = 1 << 6,
	
	#[allow(missing_docs)]
	CfbSize = 1 << 7,
	
	#[allow(missing_docs)]
	PeakBitRate = 1 << 8,
	
	#[allow(missing_docs)]
	QuantizationParameter = 1 << 9,
	
	#[allow(missing_docs)]
	SynchronizationAndLongTermReferenceFrame = 1 << 10,
	
	#[allow(missing_docs)]
	LongTermBuffer = 1 << 11,
	
	#[allow(missing_docs)]
	PictureLongTermReference = 1 << 12,
	
	#[allow(missing_docs)]
	LtrValidation = 1 << 13,
	
	#[allow(missing_docs)]
	LevelIdc = 1 << 14,
	
	#[allow(missing_docs)]
	SeiMessage = 1 << 15,
	
	#[allow(missing_docs)]
	QpRange = 1 << 16,
	
	#[allow(missing_docs)]
	PriorityIdentifier = 1 << 17,
	
	#[allow(missing_docs)]
	StartOrStopLayerOrView = 1 << 18,
	
	#[allow(missing_docs)]
	ErrorResiliency = 1 << 19,
}
