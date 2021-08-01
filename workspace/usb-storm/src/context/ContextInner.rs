// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// Designed so that when the default libusb context is held in a static variable, such as a SyncLazyCell, libusb_exit() is still called even though a static reference is held.
///
/// Also designed so that if a static reference is then later used after being the only held reference, the libusb default context is re-initialized.
#[derive(Debug)]
struct ContextInner
{
	libusb_context: *mut libusb_context,
	
	reference_count: AtomicUsize,
}

impl ContextInner
{
	const MinimumReferenceCount: usize = 1;
	
	const NoReferenceCount: usize = Self::MinimumReferenceCount - 1;
	
	const ReferenceChange: usize = 1;
	
	#[inline(always)]
	fn decrement(&self) -> (NonZeroUsize, bool)
	{
		debug_assert_ne!(self.current_reference_count(), Self::NoReferenceCount);
		
		let previous_reference_count = self.reference_count.fetch_sub(Self::ReferenceChange, SeqCst);
		(new_non_zero_usize(previous_reference_count), self.is_default_libusb_context())
	}
	
	#[inline(always)]
	fn increment(&self) -> (usize, bool)
	{
		debug_assert_ne!(self.current_reference_count(), Self::NoReferenceCount);
		
		let previous_reference_count = self.reference_count.fetch_add(Self::ReferenceChange, SeqCst);
		(previous_reference_count, self.is_default_libusb_context())
	}
	
	#[inline(always)]
	fn reinitialize() -> Result<(), ContextInitializationError>
	{
		Self::initialize(null_mut())
	}
	
	#[inline(always)]
	fn uninitialize(&self)
	{
		unsafe { libusb_exit(self.libusb_context) }
	}
	
	#[inline(always)]
	fn initialize(libusb_context_pointer: *mut *mut libusb_context) -> Result<(), ContextInitializationError>
	{
		use ContextInitializationError::*;
		
		let result = unsafe { libusb_init(libusb_context_pointer) };
		if likely!(result == 0)
		{
			Ok(())
		}
		else if likely!(result < 0)
		{
			let error = match result
			{
				LIBUSB_ERROR_IO => InputOutputError,
				
				LIBUSB_ERROR_INVALID_PARAM => unreachable!("Windows and Linux have a 4096 byte transfer limit (including setup byte)"),
				
				LIBUSB_ERROR_ACCESS => AccessDenied,
				
				LIBUSB_ERROR_NO_DEVICE => NoDevice,
				
				LIBUSB_ERROR_NOT_FOUND => RequestedResourceNotFound,
				
				LIBUSB_ERROR_BUSY => unreachable!("Should not have been called from an event handling context"),
				
				LIBUSB_ERROR_TIMEOUT => TimedOut,
				
				LIBUSB_ERROR_OVERFLOW => BufferOverflow,
				
				LIBUSB_ERROR_PIPE => Pipe,
				
				LIBUSB_ERROR_INTERRUPTED => unreachable!("Does not invoke handle_events()"),
				
				LIBUSB_ERROR_NO_MEM => OutOfMemoryInLibusb,
				
				LIBUSB_ERROR_NOT_SUPPORTED => NotSupported,
				
				-98 ..= -13 => panic!("Newly defined error code {}", result),
				
				LIBUSB_ERROR_OTHER => Other,
				
				_ => unreachable!("LIBUSB_ERROR out of range: {}", result)
			};
			Err(error)
		}
		else
		{
			unreachable!("Positive result {} from libusb_init()")
		}
	}
	
	#[inline(always)]
	const fn is_default_libusb_context(&self) -> bool
	{
		self.libusb_context.is_null()
	}
	
	#[inline(always)]
	fn current_reference_count(&self) -> usize
	{
		self.reference_count.load(SeqCst)
	}
}
