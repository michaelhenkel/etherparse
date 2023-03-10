use super::super::*;

use std::io;
use std::slice::from_raw_parts;

///MPLS header.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct MplsHeader {
    // A 20-bit label value.
    pub label: u32,
    // A 3-bit Traffic Class field for QoS (quality of service) priority and ECN .
    pub tc: u8,
    // A 1-bit bottom of stack flag. If this is set, it signifies that the current label is the last in the stack.
    pub s: bool,
    // An 8-bit TTL (time to live) field.
    pub ttl: u8,
}

impl SerializedSize for MplsHeader {
    /// Serialized size of the header in bytes.
    const SERIALIZED_SIZE: usize = 4;
}

impl MplsHeader{

    /// Read an MplsHeader from a slice and return the header & unused parts of the slice.
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Result<(MplsHeader, &[u8]), ReadError> {
        Ok((
            MplsHeaderSlice::from_slice(slice)?.to_header(),
            &slice[MplsHeader::SERIALIZED_SIZE .. ]
        ))
    }

    #[inline]
    pub fn from_bytes(bytes: [u8;4]) -> MplsHeader {
        MplsHeader{
            label: u32::from_be_bytes(
                [
                    bytes[0],
                    bytes[1],
                    (bytes[2] >> 4) & 0b0000_1111u8,
                    0b0000_0000u8
                ]
            ),
            tc: (bytes[2] >> 4) & 0b0000_111u8,
            s: 0 != (bytes[2] & 0b0001_0001u8),
            ttl: u8::from_be_bytes([bytes[3]])
        }
    }

    /// Read a MPLS header
    pub fn read<T: io::Read + io::Seek + Sized >(reader: &mut T) -> Result<MplsHeader, io::Error> {
        let buffer = {
            let mut buffer : [u8; MplsHeader::SERIALIZED_SIZE] = [0;MplsHeader::SERIALIZED_SIZE];
            reader.read_exact(&mut buffer)?;
            buffer
        };

        Ok(MplsHeaderSlice{
            slice: &buffer
        }.to_header())
    }

    /// Write the MPLS header
    #[inline]
    pub fn write<T: io::Write + Sized>(&self, writer: &mut T) -> Result<(), WriteError> {
        writer.write_all(&self.to_bytes()?)?;
        Ok(())
    }

    /// Length of the serialized header in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        4
    }

    /// Returns the serialized form of the header or an value error in case
    /// the header values are outside of range.
    #[inline]
    pub fn to_bytes(&self) -> Result<[u8;4], ValueError> {
        use crate::ErrorField::*;
        // check value ranges
        max_check_u8(self.tc, 0x7, MplsTc)?;
        max_check_u32(self.label, 0xfffff, MplsLabel)?;

        // serialize
        let label_be = self.label.to_be_bytes();
        let tc_be = self.tc.to_be_bytes();
        let ttl_be = self.ttl.to_be_bytes();
        Ok( [
            label_be[3],
            label_be[2],
            (
                if self.s {
                    label_be[1] | 0b1000_0000u8
                } else {
                    label_be[1]
                } | (tc_be[0] << 4)
            ),
            ttl_be[0],
        ])
    }   


}

///A slice containing an mpls header of a network package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MplsHeaderSlice<'a> {
    slice: &'a [u8]
}

impl<'a> MplsHeaderSlice<'a> {

    /// Creates a ethernet slice from an other slice.
    pub fn from_slice(slice: &'a[u8]) -> Result<MplsHeaderSlice<'a>, ReadError>{
        //check length
        use crate::ReadError::*;
        if slice.len() < MplsHeader::SERIALIZED_SIZE {
            return Err(UnexpectedEndOfSlice(MplsHeader::SERIALIZED_SIZE));
        }

        //all done
        Ok(MplsHeaderSlice {
            // SAFETY:
            // Safe as slice length is checked to be at least
            // MplsHeaderSlice::SERIALIZED_SIZE (4) before this.
            slice: unsafe {
                from_raw_parts(
                    slice.as_ptr(),
                    MplsHeader::SERIALIZED_SIZE
                )
            }
        })
    }

    /// Returns the slice containing the mpls header
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Read the label
    #[inline]
    pub fn label(&self) -> u32 {
        u32::from_be_bytes(
            // SAFETY:
            // Slice len checked in constructor to be at least 4.
            unsafe {
                [
                    0,
                    *self.slice.get_unchecked(2) & 0xf,
                    *self.slice.get_unchecked(1),
                    *self.slice.get_unchecked(0),
                ]
            }
        )
    }

    /// Read the "tc" field from the slice. This is a 3 bit number which refers to the IEEE 802.1p class of service and maps to the frame priority level.
    #[inline]
    pub fn tc(&self) -> u8 {
        // SAFETY:
        // Slice len checked in constructor to be at least 4.
        unsafe {
            *self.slice.get_unchecked(2) << 1 >> 5
        }
    }

    /// Read the "drop_eligible_indicator" flag from the slice. Indicates that the frame may be dropped under the presence of congestion.
    #[inline]
    pub fn s(&self) -> bool {
        // SAFETY:
        // Slice len checked in constructor to be at least 4.
        unsafe {
            0 != (*self.slice.get_unchecked(2) & 0b1000_0000)
        }
    }


    /// Read the "drop_eligible_indicator" flag from the slice. Indicates that the frame may be dropped under the presence of congestion.
    #[inline]
    pub fn ttl(&self) -> u8 {
        // SAFETY:
        // Slice len checked in constructor to be at least 4.
        unsafe {
            *self.slice.get_unchecked(3)
        }
    }
        


    /// Decode all the fields and copy the results to a Ipv4Header struct
    pub fn to_header(&self) -> MplsHeader {
        MplsHeader {
            label: self.label(),
            tc: self.tc(),
            s: self.s(),
            ttl: self.ttl(),
        }
    }
}

