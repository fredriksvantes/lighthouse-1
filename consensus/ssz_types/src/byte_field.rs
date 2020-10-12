use crate::{length::Variable, length::Fixed, tree_hash::bytefield_bytes_tree_hash_root};
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

/// A heap-allocated, ordered, variable-length collection of `bool` values, limited to `N` bits.
pub type ByteList<N> = Bytefield<Variable<N>>;

/// A heap-allocated, ordered, fixed-length collection of `bool` values, with `N` bits.
///
/// See [Bytefield](struct.Bytefield.html) documentation.
pub type ByteVector<N> = Bytefield<Fixed<N>>;

/// A heap-allocated, ordered, fixed-length, collection of `bool` values. Use of
/// [`ByteList`](type.ByteList.html) or [`ByteVector`](type.ByteVector.html) type aliases is preferred
/// over direct use of this struct.
///
/// The `T` type parameter is used to define length behaviour with the `Variable` or `Fixed` marker
/// structs.
///
/// The length of the Bytefield is set at instantiation (i.e., runtime, not compile time). However,
/// use with a `Variable` sets a type-level (i.e., compile-time) maximum length and `Fixed`
/// provides a type-level fixed length.
///
/// ## Example
///
/// The example uses the following crate-level type aliases:
///
/// - `ByteList<N>` is an alias for `Bytefield<Variable<N>>`
/// - `ByteVector<N>` is an alias for `Bytefield<Fixed<N>>`
///
/// ```
/// use ssz_types::{ByteVector, ByteList, typenum};
///
/// // `ByteList` has a type-level maximum length. The length of the list is specified at runtime
/// // and it must be less than or equal to `N`. After instantiation, `ByteList` cannot grow or
/// // shrink.
/// type ByteList8 = ByteList<typenum::U8>;
///
/// // Creating a `ByteList` with a larger-than-`N` capacity returns `None`.
/// assert!(ByteList8::with_capacity(9).is_err());
///
/// let mut bitlist = ByteList8::with_capacity(4).unwrap();  // `ByteList` permits a capacity of less than the maximum.
/// assert!(bitlist.set(3, true).is_ok());  // Setting inside the instantiation capacity is permitted.
/// assert!(bitlist.set(5, true).is_err());  // Setting outside that capacity is not.
///
/// // `ByteVector` has a type-level fixed length. Unlike `ByteList`, it cannot be instantiated with a custom length
/// // or grow/shrink.
/// type ByteVector8 = ByteVector<typenum::U8>;
///
/// let mut bitvector = ByteVector8::new();
/// assert_eq!(bitvector.len(), 8); // `ByteVector` length is fixed at the type-level.
/// assert!(bitvector.set(7, true).is_ok());  // Setting inside the capacity is permitted.
/// assert!(bitvector.set(9, true).is_err());  // Setting outside the capacity is not.
///
/// ```
///
/// ## Note
///
/// The internal representation of the bitfield is the same as that required by SSZ. The lowest
/// byte (by `Vec` index) stores the lowest bit-indices and the right-most bit stores the lowest
/// bit-index. E.g., `vec![0b0000_0001, 0b0000_0010]` has bits `0, 9` set.
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
        println!("SELF FROM BYTES {:?}", bytes.len());

        Ok(Self {
            bytes,
            len: 0,
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
        // Note: we use `as_slice` because it does _not_ have the length-delimiting bit set (or
        // present).
        let root = bytefield_bytes_tree_hash_root::<N>(self.as_slice());
        tree_hash::mix_in_length(&root, self.len())
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
        bytefield_bytes_tree_hash_root::<N>(self.as_slice())
    }
}

// #[cfg(feature = "arbitrary")]
// impl<N: 'static + Unsigned> arbitrary::Arbitrary for Bytefield<Fixed<N>> {
//     fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
//         let size = N::to_usize();
//         let mut vec: Vec<u8> = vec![0u8; size];
//         u.fill_buffer(&mut vec)?;
//         Ok(Self::from_bytes(vec).map_err(|_| arbitrary::Error::IncorrectFormat)?)
//     }
// }

// #[cfg(feature = "arbitrary")]
// impl<N: 'static + Unsigned> arbitrary::Arbitrary for Bytefield<Variable<N>> {
//     fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
//         let max_size = N::to_usize();
//         let rand = usize::arbitrary(u)?;
//         let size = std::cmp::min(rand, max_size);
//         let mut vec: Vec<u8> = vec![0u8; size];
//         u.fill_buffer(&mut vec)?;
//         Ok(Self::from_bytes(vec).map_err(|_| arbitrary::Error::IncorrectFormat)?)
//     }
// }

// #[cfg(test)]
// mod bitvector {
//     use super::*;
//     use crate::BitVector;

//     pub type BitVector0 = BitVector<typenum::U0>;
//     pub type BitVector1 = BitVector<typenum::U1>;
//     pub type BitVector4 = BitVector<typenum::U4>;
//     pub type BitVector8 = BitVector<typenum::U8>;
//     pub type BitVector16 = BitVector<typenum::U16>;
//     pub type BitVector64 = BitVector<typenum::U64>;

//     #[test]
//     fn ssz_encode() {
//         assert_eq!(BitVector0::new().as_ssz_bytes(), vec![0b0000_0000]);
//         assert_eq!(BitVector1::new().as_ssz_bytes(), vec![0b0000_0000]);
//         assert_eq!(BitVector4::new().as_ssz_bytes(), vec![0b0000_0000]);
//         assert_eq!(BitVector8::new().as_ssz_bytes(), vec![0b0000_0000]);
//         assert_eq!(
//             BitVector16::new().as_ssz_bytes(),
//             vec![0b0000_0000, 0b0000_0000]
//         );

//         let mut b = BitVector8::new();
//         for i in 0..8 {
//             b.set(i, true).unwrap();
//         }
//         assert_eq!(b.as_ssz_bytes(), vec![255]);

//         let mut b = BitVector4::new();
//         for i in 0..4 {
//             b.set(i, true).unwrap();
//         }
//         assert_eq!(b.as_ssz_bytes(), vec![0b0000_1111]);
//     }

//     #[test]
//     fn ssz_decode() {
//         assert!(BitVector0::from_ssz_bytes(&[0b0000_0000]).is_ok());
//         assert!(BitVector0::from_ssz_bytes(&[0b0000_0001]).is_err());
//         assert!(BitVector0::from_ssz_bytes(&[0b0000_0010]).is_err());

//         assert!(BitVector1::from_ssz_bytes(&[0b0000_0001]).is_ok());
//         assert!(BitVector1::from_ssz_bytes(&[0b0000_0010]).is_err());
//         assert!(BitVector1::from_ssz_bytes(&[0b0000_0100]).is_err());
//         assert!(BitVector1::from_ssz_bytes(&[0b0000_0000, 0b0000_0000]).is_err());

//         assert!(BitVector8::from_ssz_bytes(&[0b0000_0000]).is_ok());
//         assert!(BitVector8::from_ssz_bytes(&[1, 0b0000_0000]).is_err());
//         assert!(BitVector8::from_ssz_bytes(&[0b0000_0000, 1]).is_err());
//         assert!(BitVector8::from_ssz_bytes(&[0b0000_0001]).is_ok());
//         assert!(BitVector8::from_ssz_bytes(&[0b0000_0010]).is_ok());
//         assert!(BitVector8::from_ssz_bytes(&[0b0000_0100, 0b0000_0001]).is_err());
//         assert!(BitVector8::from_ssz_bytes(&[0b0000_0100, 0b0000_0010]).is_err());
//         assert!(BitVector8::from_ssz_bytes(&[0b0000_0100, 0b0000_0100]).is_err());

//         assert!(BitVector16::from_ssz_bytes(&[0b0000_0000]).is_err());
//         assert!(BitVector16::from_ssz_bytes(&[0b0000_0000, 0b0000_0000]).is_ok());
//         assert!(BitVector16::from_ssz_bytes(&[1, 0b0000_0000, 0b0000_0000]).is_err());
//     }

//     #[test]
//     fn ssz_round_trip() {
//         assert_round_trip(BitVector0::new());

//         let mut b = BitVector1::new();
//         b.set(0, true).unwrap();
//         assert_round_trip(b);

//         let mut b = BitVector8::new();
//         for j in 0..8 {
//             if j % 2 == 0 {
//                 b.set(j, true).unwrap();
//             }
//         }
//         assert_round_trip(b);

//         let mut b = BitVector8::new();
//         for j in 0..8 {
//             b.set(j, true).unwrap();
//         }
//         assert_round_trip(b);

//         let mut b = BitVector16::new();
//         for j in 0..16 {
//             if j % 2 == 0 {
//                 b.set(j, true).unwrap();
//             }
//         }
//         assert_round_trip(b);

//         let mut b = BitVector16::new();
//         for j in 0..16 {
//             b.set(j, true).unwrap();
//         }
//         assert_round_trip(b);
//     }

//     fn assert_round_trip<T: Encode + Decode + PartialEq + std::fmt::Debug>(t: T) {
//         assert_eq!(T::from_ssz_bytes(&t.as_ssz_bytes()).unwrap(), t);
//     }

//     #[test]
//     fn ssz_bytes_len() {
//         for i in 0..64 {
//             let mut bitfield = BitVector64::new();
//             for j in 0..i {
//                 bitfield.set(j, true).expect("should set bit in bounds");
//             }
//             let bytes = bitfield.as_ssz_bytes();
//             assert_eq!(bitfield.ssz_bytes_len(), bytes.len(), "i = {}", i);
//         }
//     }

//     #[test]
//     fn excess_bits_nimbus() {
//         let bad = vec![0b0001_1111];

//         assert!(BitVector4::from_ssz_bytes(&bad).is_err());
//     }
// }

#[cfg(test)]
#[allow(clippy::cognitive_complexity)]
mod bytelist {
    use super::*;
    use crate::ByteList;

    pub type ByteList0 = ByteList<typenum::U0>;
    pub type ByteList1 = ByteList<typenum::U1>;
    pub type ByteList8 = ByteList<typenum::U8>;
    pub type ByteList16 = ByteList<typenum::U16>;
    pub type ByteList1024 = ByteList<typenum::U1024>;

    #[test]
    fn ssz_encode() {
        assert_eq!(
            ByteList0::with_capacity(0).unwrap().as_ssz_bytes(),
            vec![0b0000_00001],
        );

        assert_eq!(
            ByteList1::with_capacity(0).unwrap().as_ssz_bytes(),
            vec![0b0000_00001],
        );

        assert_eq!(
            ByteList1::with_capacity(1).unwrap().as_ssz_bytes(),
            vec![0b0000_00010],
        );

        assert_eq!(
            ByteList8::with_capacity(8).unwrap().as_ssz_bytes(),
            vec![0b0000_0000, 0b0000_0001],
        );

        assert_eq!(
            ByteList8::with_capacity(7).unwrap().as_ssz_bytes(),
            vec![0b1000_0000]
        );

        let mut b = ByteList8::with_capacity(8).unwrap();
        for i in 0..8 {
            b.set(i, true).unwrap();
        }
        assert_eq!(b.as_ssz_bytes(), vec![255, 0b0000_0001]);

        let mut b = ByteList8::with_capacity(8).unwrap();
        for i in 0..4 {
            b.set(i, true).unwrap();
        }
        assert_eq!(b.as_ssz_bytes(), vec![0b0000_1111, 0b0000_0001]);

        assert_eq!(
            ByteList16::with_capacity(16).unwrap().as_ssz_bytes(),
            vec![0b0000_0000, 0b0000_0000, 0b0000_0001]
        );
    }

//     #[test]
//     fn ssz_decode() {
//         assert!(BitList0::from_ssz_bytes(&[]).is_err());
//         assert!(BitList1::from_ssz_bytes(&[]).is_err());
//         assert!(BitList8::from_ssz_bytes(&[]).is_err());
//         assert!(BitList16::from_ssz_bytes(&[]).is_err());

//         assert!(BitList0::from_ssz_bytes(&[0b0000_0000]).is_err());
//         assert!(BitList1::from_ssz_bytes(&[0b0000_0000, 0b0000_0000]).is_err());
//         assert!(BitList8::from_ssz_bytes(&[0b0000_0000]).is_err());
//         assert!(BitList16::from_ssz_bytes(&[0b0000_0000]).is_err());

//         assert!(BitList0::from_ssz_bytes(&[0b0000_0001]).is_ok());
//         assert!(BitList0::from_ssz_bytes(&[0b0000_0010]).is_err());

//         assert!(BitList1::from_ssz_bytes(&[0b0000_0001]).is_ok());
//         assert!(BitList1::from_ssz_bytes(&[0b0000_0010]).is_ok());
//         assert!(BitList1::from_ssz_bytes(&[0b0000_0100]).is_err());

//         assert!(BitList8::from_ssz_bytes(&[0b0000_0001]).is_ok());
//         assert!(BitList8::from_ssz_bytes(&[0b0000_0010]).is_ok());
//         assert!(BitList8::from_ssz_bytes(&[0b0000_0001, 0b0000_0001]).is_ok());
//         assert!(BitList8::from_ssz_bytes(&[0b0000_0001, 0b0000_0010]).is_err());
//         assert!(BitList8::from_ssz_bytes(&[0b0000_0001, 0b0000_0100]).is_err());
//     }

//     #[test]
//     fn ssz_decode_extra_bytes() {
//         assert!(BitList0::from_ssz_bytes(&[0b0000_0001, 0b0000_0000]).is_err());
//         assert!(BitList1::from_ssz_bytes(&[0b0000_0001, 0b0000_0000]).is_err());
//         assert!(BitList8::from_ssz_bytes(&[0b0000_0001, 0b0000_0000]).is_err());
//         assert!(BitList16::from_ssz_bytes(&[0b0000_0001, 0b0000_0000]).is_err());
//         assert!(BitList1024::from_ssz_bytes(&[0b1000_0000, 0]).is_err());
//         assert!(BitList1024::from_ssz_bytes(&[0b1000_0000, 0, 0]).is_err());
//         assert!(BitList1024::from_ssz_bytes(&[0b1000_0000, 0, 0, 0, 0]).is_err());
//     }

//     #[test]
//     fn ssz_round_trip() {
//         assert_round_trip(BitList0::with_capacity(0).unwrap());

//         for i in 0..2 {
//             assert_round_trip(BitList1::with_capacity(i).unwrap());
//         }
//         for i in 0..9 {
//             assert_round_trip(BitList8::with_capacity(i).unwrap());
//         }
//         for i in 0..17 {
//             assert_round_trip(BitList16::with_capacity(i).unwrap());
//         }

//         let mut b = BitList1::with_capacity(1).unwrap();
//         b.set(0, true).unwrap();
//         assert_round_trip(b);

//         for i in 0..8 {
//             let mut b = BitList8::with_capacity(i).unwrap();
//             for j in 0..i {
//                 if j % 2 == 0 {
//                     b.set(j, true).unwrap();
//                 }
//             }
//             assert_round_trip(b);

//             let mut b = BitList8::with_capacity(i).unwrap();
//             for j in 0..i {
//                 b.set(j, true).unwrap();
//             }
//             assert_round_trip(b);
//         }

//         for i in 0..16 {
//             let mut b = BitList16::with_capacity(i).unwrap();
//             for j in 0..i {
//                 if j % 2 == 0 {
//                     b.set(j, true).unwrap();
//                 }
//             }
//             assert_round_trip(b);

//             let mut b = BitList16::with_capacity(i).unwrap();
//             for j in 0..i {
//                 b.set(j, true).unwrap();
//             }
//             assert_round_trip(b);
//         }
//     }

//     fn assert_round_trip<T: Encode + Decode + PartialEq + std::fmt::Debug>(t: T) {
//         assert_eq!(T::from_ssz_bytes(&t.as_ssz_bytes()).unwrap(), t);
//     }

//     #[test]
//     fn from_raw_bytes() {
//         assert!(BitList1024::from_raw_bytes(vec![0b0000_0000], 0).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b0000_0001], 1).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b0000_0011], 2).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b0000_0111], 3).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b0000_1111], 4).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b0001_1111], 5).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b0011_1111], 6).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b0111_1111], 7).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111], 8).is_ok());

//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b0000_0001], 9).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b0000_0011], 10).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b0000_0111], 11).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b0000_1111], 12).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b0001_1111], 13).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b0011_1111], 14).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b0111_1111], 15).is_ok());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b1111_1111], 16).is_ok());

//         for i in 0..8 {
//             assert!(BitList1024::from_raw_bytes(vec![], i).is_err());
//             assert!(BitList1024::from_raw_bytes(vec![0b1111_1111], i).is_err());
//             assert!(BitList1024::from_raw_bytes(vec![0b0000_0000, 0b1111_1110], i).is_err());
//         }

//         assert!(BitList1024::from_raw_bytes(vec![0b0000_0001], 0).is_err());

//         assert!(BitList1024::from_raw_bytes(vec![0b0000_0001], 0).is_err());
//         assert!(BitList1024::from_raw_bytes(vec![0b0000_0011], 1).is_err());
//         assert!(BitList1024::from_raw_bytes(vec![0b0000_0111], 2).is_err());
//         assert!(BitList1024::from_raw_bytes(vec![0b0000_1111], 3).is_err());
//         assert!(BitList1024::from_raw_bytes(vec![0b0001_1111], 4).is_err());
//         assert!(BitList1024::from_raw_bytes(vec![0b0011_1111], 5).is_err());
//         assert!(BitList1024::from_raw_bytes(vec![0b0111_1111], 6).is_err());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111], 7).is_err());

//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b0000_0001], 8).is_err());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b0000_0011], 9).is_err());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b0000_0111], 10).is_err());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b0000_1111], 11).is_err());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b0001_1111], 12).is_err());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b0011_1111], 13).is_err());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b0111_1111], 14).is_err());
//         assert!(BitList1024::from_raw_bytes(vec![0b1111_1111, 0b1111_1111], 15).is_err());
//     }

//     fn test_set_unset(num_bits: usize) {
//         let mut bitfield = BitList1024::with_capacity(num_bits).unwrap();

//         for i in 0..=num_bits {
//             if i < num_bits {
//                 // Starts as false
//                 assert_eq!(bitfield.get(i), Ok(false));
//                 // Can be set true.
//                 assert!(bitfield.set(i, true).is_ok());
//                 assert_eq!(bitfield.get(i), Ok(true));
//                 // Can be set false
//                 assert!(bitfield.set(i, false).is_ok());
//                 assert_eq!(bitfield.get(i), Ok(false));
//             } else {
//                 assert!(bitfield.get(i).is_err());
//                 assert!(bitfield.set(i, true).is_err());
//                 assert!(bitfield.get(i).is_err());
//             }
//         }
//     }

//     fn test_bytes_round_trip(num_bits: usize) {
//         for i in 0..num_bits {
//             let mut bitfield = BitList1024::with_capacity(num_bits).unwrap();
//             bitfield.set(i, true).unwrap();

//             let bytes = bitfield.clone().into_raw_bytes();
//             assert_eq!(bitfield, Bytefield::from_raw_bytes(bytes, num_bits).unwrap());
//         }
//     }

//     #[test]
//     fn set_unset() {
//         for i in 0..8 * 5 {
//             test_set_unset(i)
//         }
//     }

//     #[test]
//     fn bytes_round_trip() {
//         for i in 0..8 * 5 {
//             test_bytes_round_trip(i)
//         }
//     }

//     #[test]
//     fn into_raw_bytes() {
//         let mut bitfield = BitList1024::with_capacity(9).unwrap();
//         bitfield.set(0, true).unwrap();
//         assert_eq!(
//             bitfield.clone().into_raw_bytes(),
//             vec![0b0000_0001, 0b0000_0000]
//         );
//         bitfield.set(1, true).unwrap();
//         assert_eq!(
//             bitfield.clone().into_raw_bytes(),
//             vec![0b0000_0011, 0b0000_0000]
//         );
//         bitfield.set(2, true).unwrap();
//         assert_eq!(
//             bitfield.clone().into_raw_bytes(),
//             vec![0b0000_0111, 0b0000_0000]
//         );
//         bitfield.set(3, true).unwrap();
//         assert_eq!(
//             bitfield.clone().into_raw_bytes(),
//             vec![0b0000_1111, 0b0000_0000]
//         );
//         bitfield.set(4, true).unwrap();
//         assert_eq!(
//             bitfield.clone().into_raw_bytes(),
//             vec![0b0001_1111, 0b0000_0000]
//         );
//         bitfield.set(5, true).unwrap();
//         assert_eq!(
//             bitfield.clone().into_raw_bytes(),
//             vec![0b0011_1111, 0b0000_0000]
//         );
//         bitfield.set(6, true).unwrap();
//         assert_eq!(
//             bitfield.clone().into_raw_bytes(),
//             vec![0b0111_1111, 0b0000_0000]
//         );
//         bitfield.set(7, true).unwrap();
//         assert_eq!(
//             bitfield.clone().into_raw_bytes(),
//             vec![0b1111_1111, 0b0000_0000]
//         );
//         bitfield.set(8, true).unwrap();
//         assert_eq!(bitfield.into_raw_bytes(), vec![0b1111_1111, 0b0000_0001]);
//     }

//     #[test]
//     fn highest_set_bit() {
//         assert_eq!(
//             BitList1024::with_capacity(16).unwrap().highest_set_bit(),
//             None
//         );

//         assert_eq!(
//             BitList1024::from_raw_bytes(vec![0b0000_0001, 0b0000_0000], 16)
//                 .unwrap()
//                 .highest_set_bit(),
//             Some(0)
//         );

//         assert_eq!(
//             BitList1024::from_raw_bytes(vec![0b0000_0010, 0b0000_0000], 16)
//                 .unwrap()
//                 .highest_set_bit(),
//             Some(1)
//         );

//         assert_eq!(
//             BitList1024::from_raw_bytes(vec![0b0000_1000], 8)
//                 .unwrap()
//                 .highest_set_bit(),
//             Some(3)
//         );

//         assert_eq!(
//             BitList1024::from_raw_bytes(vec![0b0000_0000, 0b1000_0000], 16)
//                 .unwrap()
//                 .highest_set_bit(),
//             Some(15)
//         );
//     }

//     #[test]
//     fn intersection() {
//         let a = BitList1024::from_raw_bytes(vec![0b1100, 0b0001], 16).unwrap();
//         let b = BitList1024::from_raw_bytes(vec![0b1011, 0b1001], 16).unwrap();
//         let c = BitList1024::from_raw_bytes(vec![0b1000, 0b0001], 16).unwrap();

//         assert_eq!(a.intersection(&b), c);
//         assert_eq!(b.intersection(&a), c);
//         assert_eq!(a.intersection(&c), c);
//         assert_eq!(b.intersection(&c), c);
//         assert_eq!(a.intersection(&a), a);
//         assert_eq!(b.intersection(&b), b);
//         assert_eq!(c.intersection(&c), c);
//     }

//     #[test]
//     fn intersection_diff_length() {
//         let a = BitList1024::from_bytes(vec![0b0010_1110, 0b0010_1011]).unwrap();
//         let b = BitList1024::from_bytes(vec![0b0010_1101, 0b0000_0001]).unwrap();
//         let c = BitList1024::from_bytes(vec![0b0010_1100, 0b0000_0001]).unwrap();
//         let d = BitList1024::from_bytes(vec![0b0010_1110, 0b1111_1111, 0b1111_1111]).unwrap();

//         assert_eq!(a.len(), 13);
//         assert_eq!(b.len(), 8);
//         assert_eq!(c.len(), 8);
//         assert_eq!(d.len(), 23);
//         assert_eq!(a.intersection(&b), c);
//         assert_eq!(b.intersection(&a), c);
//         assert_eq!(a.intersection(&d), a);
//         assert_eq!(d.intersection(&a), a);
//     }

//     #[test]
//     fn union() {
//         let a = BitList1024::from_raw_bytes(vec![0b1100, 0b0001], 16).unwrap();
//         let b = BitList1024::from_raw_bytes(vec![0b1011, 0b1001], 16).unwrap();
//         let c = BitList1024::from_raw_bytes(vec![0b1111, 0b1001], 16).unwrap();

//         assert_eq!(a.union(&b), c);
//         assert_eq!(b.union(&a), c);
//         assert_eq!(a.union(&a), a);
//         assert_eq!(b.union(&b), b);
//         assert_eq!(c.union(&c), c);
//     }

//     #[test]
//     fn union_diff_length() {
//         let a = BitList1024::from_bytes(vec![0b0010_1011, 0b0010_1110]).unwrap();
//         let b = BitList1024::from_bytes(vec![0b0000_0001, 0b0010_1101]).unwrap();
//         let c = BitList1024::from_bytes(vec![0b0010_1011, 0b0010_1111]).unwrap();
//         let d = BitList1024::from_bytes(vec![0b0010_1011, 0b1011_1110, 0b1000_1101]).unwrap();

//         assert_eq!(a.len(), c.len());
//         assert_eq!(a.union(&b), c);
//         assert_eq!(b.union(&a), c);
//         assert_eq!(a.union(&d), d);
//         assert_eq!(d.union(&a), d);
//     }

//     #[test]
//     fn difference() {
//         let a = BitList1024::from_raw_bytes(vec![0b1100, 0b0001], 16).unwrap();
//         let b = BitList1024::from_raw_bytes(vec![0b1011, 0b1001], 16).unwrap();
//         let a_b = BitList1024::from_raw_bytes(vec![0b0100, 0b0000], 16).unwrap();
//         let b_a = BitList1024::from_raw_bytes(vec![0b0011, 0b1000], 16).unwrap();

//         assert_eq!(a.difference(&b), a_b);
//         assert_eq!(b.difference(&a), b_a);
//         assert!(a.difference(&a).is_zero());
//     }

//     #[test]
//     fn difference_diff_length() {
//         let a = BitList1024::from_raw_bytes(vec![0b0110, 0b1100, 0b0011], 24).unwrap();
//         let b = BitList1024::from_raw_bytes(vec![0b1011, 0b1001], 16).unwrap();
//         let a_b = BitList1024::from_raw_bytes(vec![0b0100, 0b0100, 0b0011], 24).unwrap();
//         let b_a = BitList1024::from_raw_bytes(vec![0b1001, 0b0001], 16).unwrap();

//         assert_eq!(a.difference(&b), a_b);
//         assert_eq!(b.difference(&a), b_a);
//     }

//     #[test]
//     fn shift_up() {
//         let mut a = BitList1024::from_raw_bytes(vec![0b1100_1111, 0b1101_0110], 16).unwrap();
//         let mut b = BitList1024::from_raw_bytes(vec![0b1001_1110, 0b1010_1101], 16).unwrap();

//         a.shift_up(1).unwrap();
//         assert_eq!(a, b);
//         a.shift_up(15).unwrap();
//         assert!(a.is_zero());

//         b.shift_up(16).unwrap();
//         assert!(b.is_zero());
//         assert!(b.shift_up(17).is_err());
//     }

//     #[test]
//     fn num_set_bits() {
//         let a = BitList1024::from_raw_bytes(vec![0b1100, 0b0001], 16).unwrap();
//         let b = BitList1024::from_raw_bytes(vec![0b1011, 0b1001], 16).unwrap();

//         assert_eq!(a.num_set_bits(), 3);
//         assert_eq!(b.num_set_bits(), 5);
//     }

//     #[test]
//     fn iter() {
//         let mut bitfield = BitList1024::with_capacity(9).unwrap();
//         bitfield.set(2, true).unwrap();
//         bitfield.set(8, true).unwrap();

//         assert_eq!(
//             bitfield.iter().collect::<Vec<bool>>(),
//             vec![false, false, true, false, false, false, false, false, true]
//         );
//     }

//     #[test]
//     fn ssz_bytes_len() {
//         for i in 1..64 {
//             let mut bitfield = BitList1024::with_capacity(i).unwrap();
//             for j in 0..i {
//                 bitfield.set(j, true).expect("should set bit in bounds");
//             }
//             let bytes = bitfield.as_ssz_bytes();
//             assert_eq!(bitfield.ssz_bytes_len(), bytes.len(), "i = {}", i);
//         }
//     }
}
