//! Linux getrandom ABI backed by the same entropy service as native protocols.
use super::{Args, EFAULT, EINVAL};
use alloc::{vec, vec::Vec};
use zeroize::Zeroizing;

const GRND_NONBLOCK: u64 = 1;
const GRND_RANDOM: u64 = 2;
const MAX_REQUEST: usize = 65536;

#[derive(Clone, Copy)]
pub(super) struct Request {
    address: usize,
    length: usize,
    nonblocking: bool,
}

impl Request {
    pub fn read(args: &Args) -> Result<Self, i32> {
        // GRND_INSECURE is deliberately unsupported: this interface never
        // supplies the scheduler PRNG as a substitute for seeded entropy.
        if args.a2 & !(GRND_NONBLOCK | GRND_RANDOM) != 0 {
            return Err(-EINVAL);
        }
        // A bounded short read is valid and keeps a guest length from driving
        // an unbounded kernel allocation or exceeding the generator's limit.
        let length = args.a1.min(MAX_REQUEST as u64) as usize;
        if length != 0
            && (args.a0 == 0
                || args
                    .a0
                    .checked_add(length as u64)
                    .is_none_or(|end| end > 0xc000_0000))
        {
            return Err(-EFAULT);
        }
        Ok(Self {
            address: args.a0 as usize,
            length,
            nonblocking: args.a2 & GRND_NONBLOCK != 0,
        })
    }

    fn bytes_with(
        self,
        fill: impl FnOnce(&mut [u8]) -> Result<(), crate::kernel::random::Unavailable>,
    ) -> Result<Zeroizing<Vec<u8>>, i32> {
        let mut bytes = Zeroizing::new(vec![0; self.length]);
        if self.length != 0 {
            fill(&mut bytes).map_err(|_| -11)?;
        }
        Ok(bytes)
    }

    /// None means a blocking caller must wait while interrupt sources collect
    /// entropy. A nonblocking caller gets EAGAIN; no weak fallback is exposed.
    pub fn step<A: crate::Arch>(self, machine: &mut A) -> Option<i32> {
        match self.bytes_with(crate::kernel::random::fill) {
            Ok(bytes) => {
                if !bytes.is_empty() {
                    machine.copy_to(self.address, &bytes);
                }
                Some(bytes.len() as i32)
            }
            Err(-11) if !self.nonblocking => None,
            Err(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(length: u64, flags: u64) -> Args {
        Args {
            a0: 4096,
            a1: length,
            a2: flags,
            a3: 0,
            a4: 0,
            a5: 0,
        }
    }

    #[test]
    fn flags_are_validated_and_large_reads_are_bounded() {
        for flags in 0..=3 {
            let request = Request::read(&args(u64::MAX, flags)).unwrap();
            assert_eq!(request.length, MAX_REQUEST);
            assert_eq!(request.nonblocking, flags & GRND_NONBLOCK != 0);
        }
        for flags in [4, 6, 8, u64::MAX] {
            assert!(matches!(Request::read(&args(8, flags)), Err(error) if error == -EINVAL));
        }
    }

    #[test]
    fn zero_length_needs_neither_a_pointer_nor_entropy() {
        let mut call = args(0, 0);
        call.a0 = 0;
        let request = Request::read(&call).unwrap();
        assert!(
            request
                .bytes_with(|_| panic!("zero-length entropy request"))
                .unwrap()
                .is_empty()
        );
        call.a1 = 1;
        assert!(matches!(Request::read(&call), Err(error) if error == -EFAULT));
        call.a0 = u64::MAX;
        assert!(matches!(Request::read(&call), Err(error) if error == -EFAULT));
        call.a0 = 0xbfff_ffff;
        call.a1 = 2;
        assert!(matches!(Request::read(&call), Err(error) if error == -EFAULT));
    }

    #[test]
    fn unavailable_entropy_does_not_return_a_successful_buffer() {
        let request = Request::read(&args(32, 0)).unwrap();
        assert_eq!(
            request
                .bytes_with(|bytes| {
                    bytes[0] = 99;
                    Err(crate::kernel::random::Unavailable)
                })
                .unwrap_err(),
            -11
        );
        let bytes = request
            .bytes_with(|bytes| {
                bytes.fill(42);
                Ok(())
            })
            .unwrap();
        assert_eq!(&bytes[..], &[42; 32]);
    }
}
