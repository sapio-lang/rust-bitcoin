// SPDX-License-Identifier: CC0-1.0

//! Bitcoin taproot keys.
//!
//! This module provides taproot keys used in Bitcoin (including reexporting secp256k1 keys).
//!

use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use actual_arbitrary::{self as arbitrary, Arbitrary, Unstructured};
use io::Write;

use crate::internal_macros::write_err;
use crate::prelude::*;
use crate::sighash::{InvalidSighashTypeError, TapSighashType};
use crate::taproot::serialized_signature::{self, SerializedSignature};

/// A BIP340-341 serialized taproot signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Signature {
    /// The underlying schnorr signature.
    pub signature: secp256k1::schnorr::Signature,
    /// The corresponding hash type.
    pub sighash_type: TapSighashType,
}

impl Signature {
    /// Deserialize from slice
    pub fn from_slice(sl: &[u8]) -> Result<Self, SigFromSliceError> {
        match sl.len() {
            64 => {
                // default type
                let signature = secp256k1::schnorr::Signature::from_slice(sl)?;
                Ok(Signature { signature, sighash_type: TapSighashType::Default })
            }
            65 => {
                let (sighash_type, signature) = sl.split_last().expect("Slice len checked == 65");
                // BIP341 encodes SIGHASH_DEFAULT by omitting the final byte.
                // Reject it here before PSBT parsing can normalize it away.
                if *sighash_type == 0 {
                    return Err(InvalidSighashTypeError(0).into());
                }
                let sighash_type = TapSighashType::from_consensus_u8(*sighash_type)?;
                let signature = secp256k1::schnorr::Signature::from_slice(signature)?;
                Ok(Signature { signature, sighash_type })
            }
            len => Err(SigFromSliceError::InvalidSignatureSize(len)),
        }
    }

    /// Serialize Signature
    ///
    /// Note: this allocates on the heap, prefer [`serialize`](Self::serialize) if vec is not needed.
    pub fn to_vec(self) -> Vec<u8> {
        let mut ser_sig = self.signature.as_ref().to_vec();
        if self.sighash_type == TapSighashType::Default {
            // default sighash type, don't add extra sighash byte
        } else {
            ser_sig.push(self.sighash_type as u8);
        }
        ser_sig
    }

    /// Serializes the signature to `writer`.
    #[inline]
    pub fn serialize_to_writer<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        let sig = self.serialize();
        sig.write_to(writer)
    }

    /// Serializes the signature (without heap allocation)
    ///
    /// This returns a type with an API very similar to that of `Box<[u8]>`.
    /// You can get a slice from it using deref coercions or turn it into an iterator.
    pub fn serialize(self) -> SerializedSignature {
        let mut buf = [0; serialized_signature::MAX_LEN];
        let ser_sig = self.signature.serialize();
        buf[..64].copy_from_slice(&ser_sig);
        let len = if self.sighash_type == TapSighashType::Default {
            // default sighash type, don't add extra sighash byte
            64
        } else {
            buf[64] = self.sighash_type as u8;
            65
        };
        SerializedSignature::from_raw_parts(buf, len)
    }
}

#[cfg(test)]
mod canonical_signature_tests {
    use super::*;

    #[test]
    fn default_is_implicit_and_every_explicit_flag_is_checked() {
        let raw = [1; 64];
        let implicit = Signature::from_slice(&raw).unwrap();
        assert_eq!(implicit.sighash_type, TapSighashType::Default);
        assert_eq!(implicit.serialize().as_ref(), raw);

        let mut explicit = raw.to_vec();
        explicit.push(0);
        for flag in 0..=u8::MAX {
            explicit[64] = flag;
            let parsed = Signature::from_slice(&explicit);
            if matches!(flag, 1 | 2 | 3 | 0x81 | 0x82 | 0x83) {
                assert_eq!(parsed.unwrap().to_vec(), explicit);
            } else {
                assert!(matches!(parsed, Err(SigFromSliceError::SighashType(_))));
            }
        }
        for length in [0, 1, 63, 66] {
            assert!(matches!(
                Signature::from_slice(&vec![1; length]),
                Err(SigFromSliceError::InvalidSignatureSize(actual)) if actual == length
            ));
        }
    }
}

/// An error constructing a [`taproot::Signature`] from a byte slice.
///
/// [`taproot::Signature`]: crate::crypto::taproot::Signature
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigFromSliceError {
    /// Invalid signature hash type.
    SighashType(InvalidSighashTypeError),
    /// A secp256k1 error.
    Secp256k1(secp256k1::Error),
    /// Invalid taproot signature size
    InvalidSignatureSize(usize),
}

impl From<Infallible> for SigFromSliceError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for SigFromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use SigFromSliceError::*;

        match *self {
            SighashType(ref e) => write_err!(f, "sighash"; e),
            Secp256k1(ref e) => write_err!(f, "secp256k1"; e),
            InvalidSignatureSize(sz) => write!(f, "invalid taproot signature size: {}", sz),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SigFromSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SigFromSliceError::*;

        match *self {
            Secp256k1(ref e) => Some(e),
            SighashType(ref e) => Some(e),
            InvalidSignatureSize(_) => None,
        }
    }
}

impl From<secp256k1::Error> for SigFromSliceError {
    fn from(e: secp256k1::Error) -> Self { Self::Secp256k1(e) }
}

impl From<InvalidSighashTypeError> for SigFromSliceError {
    fn from(err: InvalidSighashTypeError) -> Self { Self::SighashType(err) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Signature {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let arbitrary_bytes: [u8; secp256k1::constants::SCHNORR_SIGNATURE_SIZE] = u.arbitrary()?;

        Ok(Signature {
            signature: secp256k1::schnorr::Signature::from_slice(&arbitrary_bytes).unwrap(),
            sighash_type: TapSighashType::arbitrary(u)?,
        })
    }
}
