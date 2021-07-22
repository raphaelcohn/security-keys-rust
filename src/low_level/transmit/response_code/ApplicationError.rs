// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/raphaelcohn/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum ApplicationError
{
	KeyOrFileNotFound,
	
	StatesActivityOrStatesLockStatusOrStatesLockableHasWrongValue,
	
	TransactionNumberHasReachedItsLimit,
	
	InsufficientNonVolatileMemoryToCompleteCommand,

	CommandCodeNotSupported,

	CrcOrMacDoesNotMatchData,

	InvalidKeyNumberSpecified,

	LengthOfCommandStringInvalid,

	TheRequestedCommandIsNotAllowed,

	ValueOfTheParameterIsInvalid,

	RequestedAIDNotPresentOnPICC,

	UnrecoverableErrorWithinApplication,

	AuthenticationStatusDoesNotAllowTheRequestedCommand,

	AdditionalDataFrameIsExpectedToBeSent,

	OutOfBoundary,

	UnrecoverableErrorWithPICC,

	PreviousCommandWasNotFullyCompleted,

	PICCWasDisabledByAnUnrecoverableError,

	NumberOfApplicationsLimitedTo28,

	FileOrApplicationAlreadyExists,

	CouldNotCompleteNonVolatileWriteOperationDueToLossOfPower,

	SpecifiedFileNumberDoesNotExist,

	UnrecoverableErrorWithinFile,
	
	InsufficientMemoryAsNoMoreStorageAvailable,
	
	WritingToEepromNotSuccessful,
	
	IntegrityError,
	
	CandidateS2Invalid,
	
	ApplicationIsPermanentlyLocked,
	
	NoEFSelected,
	
	CandidateCurrencyCodeDoesNotMatchPurseCurrency,
	
	CandidateAmountTooHighOrAddressRangeExceeded,
	
	CandidateAmountTooLow,
	
	FIDOrRecordOrComparisonPatternNotFound,
	
	ProblemsInTheDataField,
	
	RequiredMacUnavailable,
	
	BadCurrencyPurseEngineHasNoSlotWithR3bcCurrency,
	
	R3bcCurrencyNotSupportedInPurseEngineOrSelectedFileTypeDoesNotMatchCommand,
	
	BadSequence,
	
	SlaveNotFound,
	
	MainKeysAreBlocked,
	
	BaseKey,
	
	SecureMessagingLimitedExceededForCMacKey,
	
	SecureMessagingLimitedExceededForRMacKey,
	
	SecureMessagingLimitedExceededSequenceCounter,
	
	SecureMessagingLimitedExceededRMacLength,
	
	ServiceNotAvailable,
	
	NoPinDefined,
	
	AuthenticationFailedAsAccessConditionsWereNotSatisfied,
	
	/// `ASK RANDOM` or `GIVE RANDOM`.
	AskRandomOrGiveRandomNotExecuted,
	
	PinVerificationNotSuccessful,
	
	/// `INCREASE` or `DECREASE`.
	IncreaseOrDecreaseCouldNotBeExecutedBecauseALimitHasBeenReached,
	
	IncorrectMacApplicationSpecificAuthenticationError,

	PinNotSuccessfullyVerified1PinTryLeft,
	
	PinNotSuccessfullyVerified2PinTriesLeft,
	
	PinNotSuccessfullyVerified3OrMorePinRetriesLeft,
	
	PinNotSuccessfullyVerifiedPinNotInstalled,
	
	PinNotSuccessfullyVerifiedAndPinBlockedAndUnblockTryCounterIs3,
	
	PinBlockedAndUnblockTryCounterIs1Or2,
	
	PinBlockedAndUnblockTryCounterIs3,
	
	CardholderLockWrongStatus,
	
	RMacStateWrongStatus,
	
	MissingPrivilege,
	
	DoubleAgentAidWrongParameter,
	
	DoubleAgentTypeWrongParameter,

	IncorrectCertificateType,
	
	IncorrectSessionDataSize,
	
	IncorrectDirFileRecordSize,
	
	IncorrectFciRecordSize,
	
	IncorrectCodeSize,
	
	InsufficientMemoryToLoadApplication,
	
	InvalidAid,
	
	DuplicateAid,
	
	ApplicationPreviouslyLoaded,
	
	ApplicationHistoryListFull,
	
	ApplicationNotOpen,
	
	InvalidOffset,
	
	ApplicationAlreadyLoaded,
	
	InvalidCertificate,
	
	InvalidSignature,
	
	InvalidKtu,
	
	MsmControlsNotSet,
	
	ApplicationSignatureDoesNotExist,
	
	KtuDoesNotExist,
	
	ApplicationNotLoaded,
	
	InvalidOpenCommandDataLength,
	
	InvalidStartAddressCheckDataParameterIsIncorrect,

	InvalidLengthCheckDataParameterIsIncorrect,
	
	IllegalMemoryCheckAreaCheckDataParameterIsIncorrect,

	InvalidMsmControlsCiphertext,

	MsmControlsAlreadySet,

	SetMsmControlsDataLengthLessThan2Bytes,

	InvalidMsmControlsDataLength,

	ExcessMsmControlsCiphertext,

	VerificationOfMsmControlsDataFailed,

	InvalidMcdIssuerProductionId,

	InvalidMcdIssuerId,

	InvalidSetMsmControlsDataDate,

	InvalidMcdNumber,
	
	ReservedFieldError
	{
		field: u2,
	},

	MacVerificationFailed,

	MaximumNumberOfUnblocksReached,

	CardWasNotBlocked,

	CryptoFunctionsNotAvailable,

	NoApplicationLoaded,
}
