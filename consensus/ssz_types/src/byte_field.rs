use crate::{length::Variable, length::Fixed, tree_hash::vec_tree_hash_root};
use crate::Error;
use core::marker::PhantomData;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{Decode, Encode};
use tree_hash::Hash256;
use typenum::Unsigned;

/// A marker trait applied to `Variable` and `Fixed` that defines the behaviour of a `Bytefield`.
pub trait BytefieldBehaviour: Clone {}

impl<N: Unsigned + Clone> BytefieldBehaviour for Variable<N> {}
impl<N: Unsigned + Clone> BytefieldBehaviour for Fixed<N> {}

pub type ByteList<N> = Bytefield<Variable<N>>;
pub type ByteVector<N> = Bytefield<Fixed<N>>;

#[derive(Clone, Debug, PartialEq)]
pub struct Bytefield<T> {
    bytes: Vec<u8>,
    len: usize,
    _phantom: PhantomData<T>,
}

impl<N: Unsigned + Clone> Bytefield<Variable<N>> {
    /// Instantiate with capacity for `num_bits` boolean values. The length cannot be grown or
    /// shrunk after instantiation.
    ///
    /// All bits are initialized to `false`.
    ///
    /// Returns `None` if `num_bits > N`.
    pub fn with_capacity(num_bytes: usize) -> Result<Self, Error> {
        if num_bytes <= N::to_usize() {
            Ok(Self {
                bytes: vec![0; num_bytes],
                len: num_bytes,
                _phantom: PhantomData,
            })
        } else {
            Err(Error::OutOfBounds {
                i: Self::max_len(),
                len: Self::max_len(),
            })
        }
    }

    /// Equal to `N` regardless of the value supplied to `with_capacity`.
    pub fn max_len() -> usize {
        N::to_usize()
    }

    /// Consumes `self`, returning a serialized representation.
    ///
    /// The output is faithful to the SSZ encoding of `self`, such that a leading `true` bit is
    /// used to indicate the length of the Bytefield.
    ///
    /// ## Example
    /// ```
    /// use ssz_types::{ByteList, typenum};
    ///
    /// type ByteList8 = ByteList<typenum::U8>;
    ///
    /// let b = ByteList8::with_capacity(4).unwrap();
    ///
    /// assert_eq!(b.into_bytes(), vec![0b0001_0000]);
    /// ```
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Instantiates a new instance from `bytes`. Consumes the same format that `self.into_bytes()`
    /// produces (SSZ).
    ///
    /// Returns `None` if `bytes` are not a valid encoding.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        let bytes_len = bytes.len();

        if bytes_len <= Self::max_len() {
            Self::from_raw_bytes(bytes)
        } else {
            Err(Error::OutOfBounds {
                i: Self::max_len(),
                len: Self::max_len(),
            })
        }
    }
}

impl<N: Unsigned + Clone> Bytefield<Fixed<N>> {
    /// Instantiate a new `Bytefield` with a fixed-length of `N` bits.
    ///
    /// All bits are initialized to `false`.
    pub fn new() -> Self {
        Self {
            bytes: vec![0; Self::capacity()],
            len: Self::capacity(),
            _phantom: PhantomData,
        }
    }

    /// Returns `N`, the number of bits in `Self`.
    pub fn capacity() -> usize {
        N::to_usize()
    }

    /// Consumes `self`, returning a serialized representation.
    ///
    /// The output is faithful to the SSZ encoding of `self`.
    ///
    /// ## Example
    /// ```
    /// use ssz_types::{ByteVector, typenum};
    ///
    /// type ByteVector4 = ByteVector<typenum::U4>;
    ///
    /// assert_eq!(ByteVector4::new().into_bytes(), vec![0b0000_0000]);
    /// ```
    pub fn into_bytes(self) -> Vec<u8> {
        self.into_raw_bytes()
    }

    /// Instantiates a new instance from `bytes`. Consumes the same format that `self.into_bytes()`
    /// produces (SSZ).
    ///
    /// Returns `None` if `bytes` are not a valid encoding.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        Self::from_raw_bytes(bytes)
    }
}

impl<N: Unsigned + Clone> Default for Bytefield<Fixed<N>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: BytefieldBehaviour> Bytefield<T> {
    /// Returns the number of bits stored in `self`.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if `self.len() == 0`.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the underlying bytes representation of the bitfield.
    pub fn into_raw_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns a view into the underlying bytes representation of the bitfield.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Instantiates from the given `bytes`, which are the same format as output from
    /// `self.into_raw_bytes()`.
    ///
    /// Returns `None` if:
    ///
    /// - `bytes` is not the minimal required bytes to represent a bitfield of `bit_len` bits.
    /// - `bit_len` is not a multiple of 8 and `bytes` contains set bits that are higher than, or
    /// equal to `bit_len`.
    fn from_raw_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        Ok(Self {
            len: bytes.len(),
            bytes,
            _phantom: PhantomData,
        })
    }

    /// Returns true if no bits are set.
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|byte| *byte == 0)
    }
}

impl<N: Unsigned + Clone> Encode for Bytefield<Variable<N>> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // We could likely do better than turning this into bytes and reading the length, however
        // it is kept this way for simplicity.
        self.clone().into_bytes().len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut self.clone().into_bytes())
    }
}

impl<N: Unsigned + Clone> Decode for Bytefield<Variable<N>> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        println!("FROM BYTELIST SSZTYPES!");

        Self::from_bytes(bytes.to_vec()).map_err(|e| {
            ssz::DecodeError::BytesInvalid(format!("ByteList failed to decode: {:?}", e))
        })
    }
}

impl<N: Unsigned + Clone> Encode for Bytefield<Fixed<N>> {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_slice().len()
    }

    fn ssz_fixed_len() -> usize {
        N::to_usize()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut self.clone().into_bytes())
    }
}

impl<N: Unsigned + Clone> Decode for Bytefield<Fixed<N>> {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        N::to_usize()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Self::from_bytes(bytes.to_vec()).map_err(|e| {
            ssz::DecodeError::BytesInvalid(format!("ByteVector failed to decode: {:?}", e))
        })
    }
}

impl<N: Unsigned + Clone> Serialize for Bytefield<Variable<N>> {
    /// Serde serialization is compliant with the Ethereum YAML test format.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(self.as_ssz_bytes()))
    }
}

impl<'de, N: Unsigned + Clone> Deserialize<'de> for Bytefield<Variable<N>> {
    /// Serde serialization is compliant with the Ethereum YAML test format.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
        Self::from_ssz_bytes(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("Bytefield {:?}", e)))
    }
}

impl<N: Unsigned + Clone> Serialize for Bytefield<Fixed<N>> {
    /// Serde serialization is compliant with the Ethereum YAML test format.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(self.as_ssz_bytes()))
    }
}

impl<'de, N: Unsigned + Clone> Deserialize<'de> for Bytefield<Fixed<N>> {
    /// Serde serialization is compliant with the Ethereum YAML test format.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
        Self::from_ssz_bytes(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("Bytefield {:?}", e)))
    }
}

impl<N: Unsigned + Clone> tree_hash::TreeHash for Bytefield<Variable<N>> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_root(&self) -> Hash256 {
        let vec_root = vec_tree_hash_root::<u8, N>(&self.bytes);
        tree_hash::mix_in_length(&vec_root, self.len())
    }
}

impl<N: Unsigned + Clone> tree_hash::TreeHash for Bytefield<Fixed<N>> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_root(&self) -> Hash256 {
        vec_tree_hash_root::<u8, N>(&self.bytes)
    }
}