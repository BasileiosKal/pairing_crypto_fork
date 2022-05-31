use crate::error::Error;

pub fn vec_to_byte_array<const N: usize>(
    vec: Vec<u8>,
) -> Result<[u8; N], Error> {
    use core::convert::TryFrom;
    let data_len = vec.len();
    match <[u8; N]>::try_from(vec) {
        Ok(result) => Ok(result),
        Err(_) => Err(Error::Conversion {
            cause: format!(
                "source vector size {}, expected destination byte array size \
                 {}",
                data_len, N
            ),
        }),
    }
}

/// A testable RNG
#[cfg(test)]
mod mock {
    pub struct MockRng(rand_xorshift::XorShiftRng);

    impl rand_core::SeedableRng for MockRng {
        type Seed = [u8; 16];

        fn from_seed(seed: Self::Seed) -> Self {
            Self(rand_xorshift::XorShiftRng::from_seed(seed))
        }
    }

    #[cfg(any(test, feature = "test"))]
    impl rand_core::CryptoRng for MockRng {}

    #[cfg(any(test, feature = "test"))]
    impl rand_core::RngCore for MockRng {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest)
        }

        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), rand_core::Error> {
            self.0.try_fill_bytes(dest)
        }
    }
}
