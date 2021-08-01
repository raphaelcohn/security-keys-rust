// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


/// A libusb context.
#[derive(Debug)]
#[repr(transparent)]
pub struct Context(NonNull<ContextInner>);

unsafe impl Send for Context
{
}

unsafe impl Sync for Context
{
}

impl Drop for Context
{
	#[inline(always)]
	fn drop(&mut self)
	{
		let (previous_reference_count, wraps_default_libusb_context) = self.inner().decrement();
		let previous_reference_count = previous_reference_count.get();
		
		if wraps_default_libusb_context
		{
			if previous_reference_count == (ContextInner::MinimumReferenceCount + 1)
			{
				self.uninitialize();
			}
			else if previous_reference_count == ContextInner::MinimumReferenceCount
			{
				self.free();
			}
		}
		else
		{
			if unlikely!(previous_reference_count == ContextInner::MinimumReferenceCount)
			{
				self.uninitialize();
				self.free();
			}
		}
	}
}

impl Clone for Context
{
	#[inline(always)]
	fn clone(&self) -> Self
	{
		self.fallible_clone().expect("Could not reinitialize (but this should not be possible as the default context always reinitializes on first use once the reference count has fallen to 1)")
	}
}

impl Context
{
	/// The default context.
	#[inline(always)]
	pub fn default() -> Result<Self, ContextInitializationError>
	{
		static Cell: SyncOnceCell<Context> = SyncOnceCell::new();
		let reference = Cell.get_or_try_init(|| Self::wrap_libusb_context(null_mut()))?;
		reference.fallible_clone()
	}
	
	/// A specialized context.
	#[inline(always)]
	pub fn new() -> Result<Self, ContextInitializationError>
	{
		let mut libusb_context = MaybeUninit::uninit();
		ContextInner::initialize(libusb_context.as_mut_ptr())?;
		let libusb_context = unsafe { libusb_context.assume_init() };
		match Self::wrap_libusb_context(libusb_context)
		{
			Ok(this) => Ok(this),
			
			Err(error) =>
			{
				unsafe { libusb_exit(libusb_context) }
				Err(ContextInitializationError::CouldNotAllocateMemoryInRust(error))
			}
		}
	}
	
	#[inline(always)]
	pub(crate) fn as_ptr(&self) -> *mut libusb_context
	{
		self.inner().libusb_context
	}
	
	#[inline(always)]
	fn fallible_clone(&self) -> Result<Self, ContextInitializationError>
	{
		let (previous_reference_count, wraps_default_libusb_context) = self.inner().increment();
		if wraps_default_libusb_context
		{
			if unlikely!(previous_reference_count == ContextInner::MinimumReferenceCount)
			{
				ContextInner::reinitialize()?
			}
		}
		
		Ok(Self(self.0))
	}
	
	/// `libusb_context` will NOT have been initialized if it is the default (null) context.
	/// `libusb_context` will have been initialized if it is the default (null) context.
	fn wrap_libusb_context(libusb_context: *mut libusb_context) -> Result<Self, AllocError>
	{
		let slice = Global.allocate(Self::layout())?;
		let inner: NonNull<ContextInner> = slice.as_non_null_ptr().cast();
		
		unsafe
		{
			inner.as_ptr().write
			(
				ContextInner
				{
					libusb_context,
					
					reference_count: AtomicUsize::new(ContextInner::MinimumReferenceCount)
				}
			)
		};
		
		Ok(Self(inner))
	}
	
	#[inline(always)]
	fn uninitialize(&self)
	{
		self.inner().uninitialize();
	}
	
	#[inline(always)]
	fn free(&self)
	{
		unsafe { Global.deallocate(self.0.cast(), Self::layout()) }
	}
	
	#[inline(always)]
	fn inner<'a>(&self) -> &'a ContextInner
	{
		unsafe { & * (self.0.as_ptr()) }
	}
	
	#[inline(always)]
	const fn layout() -> Layout
	{
		Layout::new::<ContextInner>()
	}
}
