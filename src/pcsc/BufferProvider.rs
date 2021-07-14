// This file is part of security-keys-rust. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT. No part of security-keys-rust, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2021 The developers of security-keys-rust. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/security-keys-rust/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct BufferProvider
{
	buffers: RefCell<Vec<Vec<u8>>>,
}

impl BufferProvider
{
	#[inline(always)]
	pub(crate) fn new(initial_number_of_buffers: usize, initial_size: usize) -> Result<Self, AllocError>
	{
		Ok
		(
			BufferProvider
			{
				buffers: RefCell::new(Vec::new_populated_fallibly(initial_number_of_buffers, |_index| Vec::try_with_capacity(initial_size))?),
			}
		)
	}
	
	fn provide_buffer(self: &Rc<Self>, size: usize) -> Result<Buffer, TryReserveError>
	{
		let mut buffers = self.buffers.borrow_mut();
		let mut buffer = match buffers.pop()
		{
			None => Vec::new_with_capacity(size)?,
			
			Some(mut buffer) =>
			{
				let capacity = buffer.capacity();
				if unlikely!(capacity < size)
				{
					buffer.try_reserve_exact(size - capacity)?;
				}
				buffer
			}
		};
		buffer.set_length(size);
		Ok
		(
			Buffer
			{
				buffer: ManuallyDrop::new(buffer),
				
				buffer_provider: self.clone(),
			}
		)
	}
	
	#[inline(always)]
	fn gift(self: &Rc<Self>, mut buffer: Vec<u8>)
	{
		buffer.clear();
		let mut buffers = self.buffers.borrow_mut();
		buffers.push(buffer)
	}
}
