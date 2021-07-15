// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


use self::c::constants::ATR_BUFFER_SIZE;
use self::c::constants::INFINITE;
use self::c::constants::MAX_BUFFER_SIZE;
use self::c::constants::MAX_BUFFER_SIZE_EXTENDED;
use self::c::constants::MAX_READERNAME;
use self::c::constants::SCARD_EJECT_CARD;
use self::c::constants::SCARD_E_INSUFFICIENT_BUFFER;
use self::c::constants::SCARD_E_INVALID_HANDLE;
use self::c::constants::SCARD_E_INVALID_PARAMETER;
use self::c::constants::SCARD_E_INVALID_VALUE;
use self::c::constants::SCARD_E_NO_MEMORY;
use self::c::constants::SCARD_E_NO_READERS_AVAILABLE;
use self::c::constants::SCARD_E_NO_SERVICE;
use self::c::constants::SCARD_E_NO_SMARTCARD;
use self::c::constants::SCARD_E_NOT_TRANSACTED;
use self::c::constants::SCARD_E_PROTO_MISMATCH;
use self::c::constants::SCARD_E_READER_UNAVAILABLE;
use self::c::constants::SCARD_E_SHARING_VIOLATION;
use self::c::constants::SCARD_E_UNKNOWN_READER;
use self::c::constants::SCARD_E_UNSUPPORTED_FEATURE;
use self::c::constants::SCARD_F_COMM_ERROR;
use self::c::constants::SCARD_F_INTERNAL_ERROR;
use self::c::constants::SCARD_LEAVE_CARD;
use self::c::constants::SCARD_PROTOCOL_RAW;
use self::c::constants::SCARD_PROTOCOL_T0;
use self::c::constants::SCARD_PROTOCOL_T15;
use self::c::constants::SCARD_PROTOCOL_T1;
use self::c::constants::SCARD_RESET_CARD;
use self::c::constants::SCARD_SCOPE_SYSTEM;
use self::c::constants::SCARD_SHARE_DIRECT;
use self::c::constants::SCARD_SHARE_EXCLUSIVE;
use self::c::constants::SCARD_SHARE_SHARED;
use self::c::constants::SCARD_S_SUCCESS;
use self::c::constants::SCARD_UNPOWER_CARD;
use self::c::constants::SCARD_W_REMOVED_CARD;
use self::c::constants::SCARD_W_RESET_CARD;
use self::c::constants::SCARD_W_UNPOWERED_CARD;
use self::c::constants::SCARD_W_UNRESPONSIVE_CARD;
use self::c::functions::SCARD_CTL_CODE;
use self::c::functions::SCardBeginTransaction;
use self::c::functions::SCardCancel;
use self::c::functions::SCardConnect;
use self::c::functions::SCardControl;
use self::c::functions::SCardDisconnect;
use self::c::functions::SCardEndTransaction;
use self::c::functions::SCardEstablishContext;
use self::c::functions::SCardGetAttrib;
use self::c::functions::SCardIsValidContext;
use self::c::functions::SCardListReaders;
use self::c::functions::SCardReconnect;
use self::c::functions::SCardReleaseContext;
use self::c::functions::SCardSetAttrib;
use self::c::functions::SCardStatus;
use self::c::functions::SCardTransmit;
use self::c::fundamental_types::DWORD;
use self::c::statics::g_rgSCardRawPci;
use self::c::statics::g_rgSCardT0Pci;
use self::c::statics::g_rgSCardT1Pci;
use self::c::types::SCARDCONTEXT;
use self::c::types::SCARDHANDLE;
use self::c::types::SCARD_IO_REQUEST;
use self::attributes::AttributeIdentifier;
use self::card_reader_name::CardReaderName;
use self::card_reader_name::CardReaderNames;
use self::card_reader_name::CardReaderNamesBuffer;
use self::card_state::CardReaderState;
use self::card_state::CardReaderStates;
use self::card_state::CardStatus;
use self::card_state::InsertionsAndRemovalsCount;
use self::errors::ActivityError;
use self::errors::CardCommandError;
use self::errors::ConnectCardError;
use self::errors::CardReaderStatusChangeError;
use self::errors::CardStatusError;
use self::errors::CardTransmissionError;
use self::errors::CommunicationError;
use self::errors::ReconnectionUnavailableOrCommunicationError;
use self::errors::TransactionError;
use self::errors::UnavailableOrCommunicationError;
use self::errors::UnavailableError;
use self::errors::WithDisconnectError;
use arrayvec::ArrayVec;
use libc::c_char;
use likely::likely;
use likely::unlikely;
use std::cell::Cell;
use std::cmp::max;
use std::collections::HashSet;
use std::error;
use std::mem::transmute;
use std::mem::MaybeUninit;
use std::num::NonZeroU32;
use std::ptr::null;
use std::ptr::null_mut;
use std::ptr::read;
use std::rc::Rc;
use std::thread::sleep;
use std::time::Duration;
use swiss_army_knife::get_unchecked::GetUnchecked;


/// Attributes.
pub mod attributes;


/// Card reader name.
pub mod card_reader_name;


/// Card state.
pub mod card_state;


mod c;


/// Errors.
pub mod errors;


include!("AnswerToReset.rs");
include!("CardDisposition.rs");
include!("CardSharedAccessBackOff.rs");
include!("ConnectedCard.rs");
include!("ConnectedCardOrTransaction.rs");
include!("ConnectedCardTransaction.rs");
include!("Context.rs");
include!("ContextInner.rs");
include!("ControlCode.rs");
include!("PreferredProtocols.rs");
include!("Protocol.rs");
include!("RemainingResetRetryAttempts.rs");
include!("Scope.rs");
include!("ShareModeAndPreferredProtocols.rs");
include!("Timeout.rs");
