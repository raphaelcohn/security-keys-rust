// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Based on <https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/>.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum ResponseCode
{
	Ok,
	
	ApplicationInformation(ApplicationInformation),
	
	ApplicationWarning(ApplicationWarning),
	
	ApplicationError(ApplicationError),
	
	ApplicationUnknown
	{
		sw1: u8,
		
		sw2: u8,
	},
	
	ClassNotSupported
	{
		sw2: u8,
	},

	ResponseBytesStillAvailable
	{
		number_of_bytes_still_available_using_GET_RESPONSE: u8
	},
	
	StateOfNonVolatileMemoryUnchangedWarning(StateOfNonVolatileMemoryUnchangedWarning),
	
	StateOfNonVolatileMemoryChangedWarning(StateOfNonVolatileMemoryChangedWarning),
	
	StateOfNonVolatileMemoryUnchangedError(StateOfNonVolatileMemoryUnchangedError),
	
	StateOfNonVolatileMemoryChangedError(StateOfNonVolatileMemoryChangedError),
	
	SecurityError(SecurityError),
	
	LengthError(LengthError),
	
	ClassFunctionError(ClassFunctionError),
	
	CommandNotAllowedError(CommandNotAllowedError),
	
	WrongParametersVariant1Error(WrongParametersVariant1Error),
	
	WrongParametersVariant2Error(WrongParametersVariant2Error),
	
	WrongLengthLeError(WrongLengthLeError),
	
	InstructionCodeError(InstructionCodeError),
	
	ClassCodeError(ClassCodeError),
	
	InternalExceptionError(InternalExceptionError),

	Unknown
	{
		sw1: u8,
	
		sw2: u8,
	},
}

impl ResponseCode
{
	#[inline(always)]
	fn level(self) -> ResponseLevel
	{
		use self::ResponseCode::*;
		use self::ResponseLevel::*;
		
		match self
		{
			Ok => Information,
			
			ApplicationInformation(..) => Information,
			
			ApplicationWarning(..) => Warning,
			
			ApplicationError(..) => Error,
			
			ApplicationUnknown { .. } => Error,
			
			ClassNotSupported { .. } => Error,
			
			ResponseBytesStillAvailable { .. } => Information,
			
			StateOfNonVolatileMemoryUnchangedWarning(..) => Warning,
			
			StateOfNonVolatileMemoryChangedWarning(..) => Warning,
			
			StateOfNonVolatileMemoryUnchangedError(..) => Error,
			
			StateOfNonVolatileMemoryChangedError(..) => Error,
			
			SecurityError(..) => Security,
			
			LengthError(..) => Error,
			
			ClassFunctionError(..) => Error,
			
			CommandNotAllowedError(..) => Error,
			
			WrongParametersVariant1Error(..) => Error,
			
			WrongParametersVariant2Error(..) => Error,
			
			WrongLengthLeError(..) => Error,
			
			InstructionCodeError(..) => Error,
			
			ClassCodeError(..) => Error,
			
			InternalExceptionError(..) => Error,
			
			Unknown { .. } => Error,
		}
	}
	
	#[inline(always)]
	pub(crate) fn extract_response_data_and_response_code(received_buffer: &[u8]) -> Result<(&[u8], Self), CardError>
	{
		let received_length = received_buffer.len();
		if unlikely!(received_length < 2)
		{
			return Err(CardError::TransmitReturnedLessThanTwoBytes { received_length: received_length as u8 })
		}
		let data_length = received_length - 2;
		let sw1 = received_buffer[data_length];
		let sw2 = received_buffer[data_length + 1];
	
		let this = Self::categorize_response_code(sw1, sw2);
		
		Ok((&received_buffer[ .. data_length], this))
	}
	
	#[inline(always)]
	pub(super) fn categorize_response_code(sw1: u8, sw2: u8) -> Self
	{
		use self::ApplicationError::*;
		use self::ApplicationInformation::*;
		use self::ApplicationWarning::*;
		
		match sw1
		{
			0x06 => ResponseCode::ClassNotSupported { sw2 },
			
			0x61 => ResponseCode::ResponseBytesStillAvailable { number_of_bytes_still_available_using_GET_RESPONSE: sw2 },
			
			0x62 => ResponseCode::StateOfNonVolatileMemoryUnchangedWarning(StateOfNonVolatileMemoryUnchangedWarning::categorize_response_code(sw2)),
			
			0x63 => ResponseCode::StateOfNonVolatileMemoryChangedWarning(StateOfNonVolatileMemoryChangedWarning::categorize_response_code(sw2)),
			
			0x64 => ResponseCode::StateOfNonVolatileMemoryUnchangedError(StateOfNonVolatileMemoryUnchangedError::categorize_response_code(sw2)),
			
			0x65 => ResponseCode::StateOfNonVolatileMemoryChangedError(StateOfNonVolatileMemoryChangedError::categorize_response_code(sw2)),
			
			0x66 => ResponseCode::SecurityError(SecurityError::categorize_response_code(sw2)),
			
			0x67 => ResponseCode::LengthError(LengthError::categorize_response_code(sw2)),
			
			0x68 => ResponseCode::ClassFunctionError(ClassFunctionError::categorize_response_code(sw2)),
			
			0x69 => ResponseCode::CommandNotAllowedError(CommandNotAllowedError::categorize_response_code(sw2)),
			
			0x6A => ResponseCode::WrongParametersVariant1Error(WrongParametersVariant1Error::categorize_response_code(sw2)),
			
			0x6B => ResponseCode::WrongParametersVariant2Error(WrongParametersVariant2Error::categorize_response_code(sw2)),
			
			0x6C => ResponseCode::WrongLengthLeError(WrongLengthLeError::categorize_response_code(sw2)),
			
			0x6D => ResponseCode::InstructionCodeError(InstructionCodeError::categorize_response_code(sw2)),
			
			0x6E => ResponseCode::ClassCodeError(ClassCodeError::categorize_response_code(sw2)),
			
			0x6F => ResponseCode::InternalExceptionError(InternalExceptionError::categorize_response_code(sw2)),
			
			0x90 => match sw2
			{
				0x00 => ResponseCode::Ok,
				
				0x04 => ResponseCode::ApplicationWarning(PinNotSuccessfullyVerifiedBut3OrMorePinRetriesLeft),
				
				0x08 => ResponseCode::ApplicationError(KeyOrFileNotFound),
				
				0x80 => ResponseCode::ApplicationWarning(UnblockTryCounterHasReachedZero),
				
				_ => ResponseCode::ApplicationUnknown { sw1: 0x90, sw2 },
			}
			
			0x91 => match sw2
			{
				0x00 => ResponseCode::Ok,
				
				0x01 => ResponseCode::ApplicationError(StatesActivityOrStatesLockStatusOrStatesLockableHasWrongValue),
				
				0x02 => ResponseCode::ApplicationError(TransactionNumberHasReachedItsLimit),
				
				0x03 => ResponseCode::ApplicationInformation(NoChanges),
				
				0x0E => ResponseCode::ApplicationError(InsufficientNonVolatileMemoryToCompleteCommand),
				
				0x1C => ResponseCode::ApplicationError(CommandCodeNotSupported),
				
				0x1E => ResponseCode::ApplicationError(CrcOrMacDoesNotMatchData),
				
				0x40 => ResponseCode::ApplicationError(InvalidKeyNumberSpecified),
				
				0x7E => ResponseCode::ApplicationError(LengthOfCommandStringInvalid),
				
				0x9D => ResponseCode::ApplicationError(TheRequestedCommandIsNotAllowed),
				
				0x9E => ResponseCode::ApplicationError(ValueOfTheParameterIsInvalid),
				
				0xA0 => ResponseCode::ApplicationError(RequestedAIDNotPresentOnPICC),
				
				0xA1 => ResponseCode::ApplicationError(UnrecoverableErrorWithinApplication),
				
				0xAE => ResponseCode::ApplicationError(AuthenticationStatusDoesNotAllowTheRequestedCommand),
				
				0xAF => ResponseCode::ApplicationError(AdditionalDataFrameIsExpectedToBeSent),
				
				0xBE => ResponseCode::ApplicationError(OutOfBoundary),
				
				0xC1 => ResponseCode::ApplicationError(UnrecoverableErrorWithPICC),
				
				0xCA => ResponseCode::ApplicationError(PreviousCommandWasNotFullyCompleted),
				
				0xCD => ResponseCode::ApplicationError(PICCWasDisabledByAnUnrecoverableError),
				
				0xCE => ResponseCode::ApplicationError(NumberOfApplicationsLimitedTo28),
				
				0xDE => ResponseCode::ApplicationError(FileOrApplicationAlreadyExists),
				
				0xEE => ResponseCode::ApplicationError(CouldNotCompleteNonVolatileWriteOperationDueToLossOfPower),
				
				0xF0 => ResponseCode::ApplicationError(SpecifiedFileNumberDoesNotExist),
				
				0xF1 => ResponseCode::ApplicationError(UnrecoverableErrorWithinFile),
				
				_ => ResponseCode::ApplicationUnknown { sw1: 0x91, sw2 },
			}
			
			0x92 => match sw2
			{
				0x00 ..= 0x0F => ResponseCode::ApplicationInformation(WriteToEepromSuccessful { attempts: sw2 - 0x00 }),
				
				0x10 => ResponseCode::ApplicationError(InsufficientMemoryAsNoMoreStorageAvailable),
				
				0x40 => ResponseCode::ApplicationError(WritingToEepromNotSuccessful),
				
				_ => ResponseCode::ApplicationUnknown { sw1: 0x92, sw2 },
			}
			
			0x93 => match sw2
			{
				0x01 => ResponseCode::ApplicationError(IntegrityError),
				
				0x02 => ResponseCode::ApplicationError(CandidateS2Invalid),
				
				0x03 => ResponseCode::ApplicationError(ApplicationIsPermanentlyLocked),
				
				_ => ResponseCode::ApplicationUnknown { sw1: 0x93, sw2 },
			}
			
			0x94 => match sw2
			{
				0x00 => ResponseCode::ApplicationError(NoEFSelected),
				
				0x01 => ResponseCode::ApplicationError(CandidateCurrencyCodeDoesNotMatchPurseCurrency),
				
				0x02 => ResponseCode::ApplicationError(CandidateAmountTooHighOrAddressRangeExceeded),
				
				0x03 => ResponseCode::ApplicationError(CandidateAmountTooLow),
				
				0x04 => ResponseCode::ApplicationError(FIDOrRecordOrComparisonPatternNotFound),
				
				0x05 => ResponseCode::ApplicationError(ProblemsInTheDataField),
				
				0x06 => ResponseCode::ApplicationError(RequiredMacUnavailable),
				
				0x07 => ResponseCode::ApplicationError(BadCurrencyPurseEngineHasNoSlotWithR3bcCurrency),
				
				0x08 => ResponseCode::ApplicationError(R3bcCurrencyNotSupportedInPurseEngineOrSelectedFileTypeDoesNotMatchCommand),
				
				_ => ResponseCode::ApplicationUnknown { sw1: 0x94, sw2 },
			}
			
			0x95 => match sw2
			{
				0x80 => ResponseCode::ApplicationError(BadSequence),
				
				_ => ResponseCode::ApplicationUnknown { sw1: 0x95, sw2 },
			}
			
			0x96 => match sw2
			{
				0x81 => ResponseCode::ApplicationError(SlaveNotFound),
				
				_ => ResponseCode::ApplicationUnknown { sw1: 0x96, sw2 },
			}
			
			0x97 => match sw2
			{
				0x00 => ResponseCode::ApplicationError(PinBlockedAndUnblockTryCounterIs1Or2),
				
				0x02 => ResponseCode::ApplicationError(MainKeysAreBlocked),
				
				0x04 => ResponseCode::ApplicationError(PinNotSuccessfullyVerified3OrMorePinRetriesLeft),
				
				0x84 => ResponseCode::ApplicationError(BaseKey),
				
				0x85 => ResponseCode::ApplicationError(SecureMessagingLimitedExceededForCMacKey),
				
				0x86 => ResponseCode::ApplicationError(SecureMessagingLimitedExceededForRMacKey),
				
				0x87 => ResponseCode::ApplicationError(SecureMessagingLimitedExceededSequenceCounter),
				
				0x88 => ResponseCode::ApplicationError(SecureMessagingLimitedExceededRMacLength),
				
				0x89 => ResponseCode::ApplicationError(ServiceNotAvailable),
				
				_ => ResponseCode::ApplicationUnknown { sw1: 0x97, sw2 },
			}
			
			0x98 => match sw2
			{
				0x02 => ResponseCode::ApplicationError(NoPinDefined),
				
				0x04 => ResponseCode::ApplicationError(AuthenticationFailedAsAccessConditionsWereNotSatisfied),
				
				0x35 => ResponseCode::ApplicationError(AskRandomOrGiveRandomNotExecuted),
				
				0x40 => ResponseCode::ApplicationError(PinVerificationNotSuccessful),
				
				0x50 => ResponseCode::ApplicationError(IncreaseOrDecreaseCouldNotBeExecutedBecauseALimitHasBeenReached),
				
				0x62 => ResponseCode::ApplicationError(IncorrectMacApplicationSpecificAuthenticationError),
				
				_ => ResponseCode::ApplicationUnknown { sw1: 0x98, sw2 },
			}
			
			0x99 => match sw2
			{
				0x00 => ResponseCode::ApplicationInformation(OnePinTryLeft),
				
				0x04 => ResponseCode::ApplicationError(PinNotSuccessfullyVerified1PinTryLeft),
				
				0x85 => ResponseCode::ApplicationError(CardholderLockWrongStatus),
				
				0x86 => ResponseCode::ApplicationError(MissingPrivilege),
				
				0x87 => ResponseCode::ApplicationInformation(PinNotInstalled),
				
				0x88 => ResponseCode::ApplicationError(RMacStateWrongStatus),
				
				_ => ResponseCode::ApplicationUnknown { sw1: 0x99, sw2 },
			}
			
			0x9A => match sw2
			{
				0x00 => ResponseCode::ApplicationInformation(TwoPinTriesLeft),
				
				0x04 => ResponseCode::ApplicationError(PinNotSuccessfullyVerified2PinTriesLeft),
				
				0x71 => ResponseCode::ApplicationError(DoubleAgentAidWrongParameter),
				
				0x72 => ResponseCode::ApplicationError(DoubleAgentTypeWrongParameter),
				
				_ => ResponseCode::ApplicationUnknown { sw1: 0x9A, sw2 },
			},
			
			0x9B => ResponseCode::ApplicationUnknown { sw1: 0x9B, sw2 },
			
			0x9C => ResponseCode::ApplicationUnknown { sw1: 0x9C, sw2 },
			
			0x9D => match sw2
			{
				0x05 => ResponseCode::ApplicationError(IncorrectCertificateType),
				
				0x07 => ResponseCode::ApplicationError(IncorrectSessionDataSize),
				
				0x08 => ResponseCode::ApplicationError(IncorrectDirFileRecordSize),
				
				0x09 => ResponseCode::ApplicationError(IncorrectFciRecordSize),
				
				0x0A => ResponseCode::ApplicationError(IncorrectCodeSize),
				
				0x10 => ResponseCode::ApplicationError(InsufficientMemoryToLoadApplication),
				
				0x11 => ResponseCode::ApplicationError(InvalidAid),
				
				0x12 => ResponseCode::ApplicationError(DuplicateAid),
				
				0x13 => ResponseCode::ApplicationError(ApplicationPreviouslyLoaded),
				
				0x14 => ResponseCode::ApplicationError(ApplicationHistoryListFull),
				
				0x15 => ResponseCode::ApplicationError(ApplicationNotOpen),
				
				0x17 => ResponseCode::ApplicationError(InvalidOffset),
				
				0x18 => ResponseCode::ApplicationError(ApplicationAlreadyLoaded),
				
				0x19 => ResponseCode::ApplicationError(InvalidCertificate),
				
				0x1A => ResponseCode::ApplicationError(InvalidSignature),
				
				0x1B => ResponseCode::ApplicationError(InvalidKtu),
				
				0x1D => ResponseCode::ApplicationError(MsmControlsNotSet),
				
				0x1E => ResponseCode::ApplicationError(ApplicationSignatureDoesNotExist),
				
				0x1F => ResponseCode::ApplicationError(KtuDoesNotExist),
				
				0x20 => ResponseCode::ApplicationError(ApplicationNotLoaded),
				
				0x21 => ResponseCode::ApplicationError(InvalidOpenCommandDataLength),
				
				0x30 => ResponseCode::ApplicationError(InvalidStartAddressCheckDataParameterIsIncorrect),
				
				0x31 => ResponseCode::ApplicationError(InvalidLengthCheckDataParameterIsIncorrect),
				
				0x32 => ResponseCode::ApplicationError(IllegalMemoryCheckAreaCheckDataParameterIsIncorrect),
				
				0x40 => ResponseCode::ApplicationError(InvalidMsmControlsCiphertext),
				
				0x41 => ResponseCode::ApplicationError(MsmControlsAlreadySet),
				
				0x42 => ResponseCode::ApplicationError(SetMsmControlsDataLengthLessThan2Bytes),
				
				0x43 => ResponseCode::ApplicationError(InvalidMsmControlsDataLength),
				
				0x44 => ResponseCode::ApplicationError(ExcessMsmControlsCiphertext),
				
				0x45 => ResponseCode::ApplicationError(VerificationOfMsmControlsDataFailed),
				
				0x50 => ResponseCode::ApplicationError(InvalidMcdIssuerProductionId),
				
				0x51 => ResponseCode::ApplicationError(InvalidMcdIssuerId),
				
				0x52 => ResponseCode::ApplicationError(InvalidSetMsmControlsDataDate),
				
				0x53 => ResponseCode::ApplicationError(InvalidMcdNumber),
				
				0x54 => ResponseCode::ApplicationError(ReservedFieldError { field: sw2 - 0x54 }),
				
				0x55 => ResponseCode::ApplicationError(ReservedFieldError { field: sw2 - 0x54 }),
				
				0x56 => ResponseCode::ApplicationError(ReservedFieldError { field: sw2 - 0x54 }),
				
				0x57 => ResponseCode::ApplicationError(ReservedFieldError { field: sw2 - 0x54 }),
				
				0x60 => ResponseCode::ApplicationError(MacVerificationFailed),
				
				0x61 => ResponseCode::ApplicationError(MaximumNumberOfUnblocksReached),
				
				0x62 => ResponseCode::ApplicationError(CardWasNotBlocked),
				
				0x63 => ResponseCode::ApplicationError(CryptoFunctionsNotAvailable),
				
				0x64 => ResponseCode::ApplicationError(NoApplicationLoaded),
				
				_ => ResponseCode::ApplicationUnknown { sw1: 0x9D, sw2 },
			}
			
			0x9E => match sw2
			{
				0x00 => ResponseCode::ApplicationInformation(PinNotInstalled),
				
				0x04 => ResponseCode::ApplicationError(PinNotSuccessfullyVerifiedPinNotInstalled),
				
				_ => ResponseCode::ApplicationUnknown { sw1: 0x9E, sw2 },
			}
			
			0x9F => match sw2
			{
				0x00 => ResponseCode::ApplicationError(PinBlockedAndUnblockTryCounterIs3),
				
				0x04 => ResponseCode::ApplicationError(PinNotSuccessfullyVerifiedAndPinBlockedAndUnblockTryCounterIs3),
				
				0x01 ..= 0x03 | 0x05 ..= 0xFF => ResponseCode::ApplicationInformation(CommandSuccessfulAndValueBytesAreAvailableUsingGetResponse { value: sw2 }),
			}
			
			_ => ResponseCode::Unknown { sw1, sw2 },
		}
	}
}
