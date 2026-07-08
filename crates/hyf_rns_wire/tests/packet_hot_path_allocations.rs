#![cfg(feature = "std")]

use allocation_counter::AllocationInfo;
use hyf_rns_core::{RNS_HEADER_1_LEN, RNS_HEADER_2_LEN, RNS_MTU, RnsDestinationHash};
use hyf_rns_wire::{
    RNS_CONTEXT_NONE, RNS_CONTEXT_PATH_RESPONSE, RnsDestinationType, RnsHeaderType, RnsPacketFlags,
    RnsPacketRef, RnsPacketType, RnsTransportType, RnsWireError, decode_packet, encode_flags,
    encode_packet, packet_hash, packet_truncated_hash, write_packet_hashable_part,
};
use std::hint::black_box;

const HEADER_1_DATA: [u8; 3] = [0xaa, 0xbb, 0xcc];
const HEADER_2_DATA: [u8; 4] = [0xdd, 0xee, 0xff, 0x42];
const HEADER_1_RAW_LEN: usize = RNS_HEADER_1_LEN + HEADER_1_DATA.len();
const HEADER_2_RAW_LEN: usize = RNS_HEADER_2_LEN + HEADER_2_DATA.len();
const DESTINATION_START: usize = 2;
const HEADER_1_CONTEXT_INDEX: usize = RNS_HEADER_1_LEN - 1;
const HEADER_2_TRANSPORT_START: usize = 2;
const HEADER_2_DESTINATION_START: usize = HEADER_2_TRANSPORT_START + 16;
const HEADER_2_CONTEXT_INDEX: usize = RNS_HEADER_2_LEN - 1;

#[test]
fn header_1_packet_hot_paths_allocate_zero_heap_memory() -> Result<(), RnsWireError> {
    let raw = header_1_raw();
    let packet = header_1_packet_ref(&HEADER_1_DATA);
    let allocations = measure_hot_path(|| run_hot_paths(&raw, packet))?;

    assert_zero_allocations(allocations);
    Ok(())
}

#[test]
fn header_2_packet_hot_paths_allocate_zero_heap_memory() -> Result<(), RnsWireError> {
    let raw = header_2_raw();
    let packet = header_2_packet_ref(&HEADER_2_DATA);
    let allocations = measure_hot_path(|| run_hot_paths(&raw, packet))?;

    assert_zero_allocations(allocations);
    Ok(())
}

fn measure_hot_path(
    run_hot_path: impl FnOnce() -> Result<(), RnsWireError>,
) -> Result<AllocationInfo, RnsWireError> {
    let mut result: Result<(), RnsWireError> = Ok(());
    let allocations = allocation_counter::measure(|| {
        result = run_hot_path();
    });

    result?;
    Ok(allocations)
}

fn run_hot_paths(raw: &[u8], packet: RnsPacketRef<'_>) -> Result<(), RnsWireError> {
    let decoded = black_box(decode_packet(black_box(raw))?);
    black_box(decoded);

    let mut encoded = [0; RNS_MTU];
    let encoded_len = black_box(encode_packet(black_box(packet), black_box(&mut encoded))?);
    black_box(encoded_len);

    let mut hashable = [0; RNS_MTU];
    let hashable_len = black_box(write_packet_hashable_part(
        black_box(raw),
        black_box(&mut hashable),
    )?);
    black_box(hashable_len);

    let full_hash = black_box(packet_hash(black_box(raw))?);
    black_box(full_hash);
    let truncated_hash = black_box(packet_truncated_hash(black_box(raw))?);
    black_box(truncated_hash);

    Ok(())
}

fn assert_zero_allocations(allocations: AllocationInfo) {
    assert_eq!(allocations.count_total, 0);
    assert_eq!(allocations.count_current, 0);
    assert_eq!(allocations.count_max, 0);
    assert_eq!(allocations.bytes_total, 0);
    assert_eq!(allocations.bytes_current, 0);
    assert_eq!(allocations.bytes_max, 0);
}

fn header_1_raw() -> [u8; HEADER_1_RAW_LEN] {
    let mut raw = [0; HEADER_1_RAW_LEN];
    raw[0] = encode_flags(header_1_flags());
    raw[1] = 7;
    raw[DESTINATION_START..HEADER_1_CONTEXT_INDEX].copy_from_slice(&[0x11; 16]);
    raw[HEADER_1_CONTEXT_INDEX] = RNS_CONTEXT_NONE;
    raw[RNS_HEADER_1_LEN..].copy_from_slice(&HEADER_1_DATA);
    raw
}

fn header_2_raw() -> [u8; HEADER_2_RAW_LEN] {
    let mut raw = [0; HEADER_2_RAW_LEN];
    raw[0] = encode_flags(header_2_flags());
    raw[1] = 9;
    raw[HEADER_2_TRANSPORT_START..HEADER_2_DESTINATION_START].copy_from_slice(&[0x22; 16]);
    raw[HEADER_2_DESTINATION_START..HEADER_2_CONTEXT_INDEX].copy_from_slice(&[0x33; 16]);
    raw[HEADER_2_CONTEXT_INDEX] = RNS_CONTEXT_PATH_RESPONSE;
    raw[RNS_HEADER_2_LEN..].copy_from_slice(&HEADER_2_DATA);
    raw
}

fn header_1_packet_ref(data: &[u8]) -> RnsPacketRef<'_> {
    RnsPacketRef {
        flags: header_1_flags(),
        hops: 7,
        transport_id: None,
        destination_hash: RnsDestinationHash::new([0x11; 16]),
        context: RNS_CONTEXT_NONE,
        data,
    }
}

fn header_2_packet_ref(data: &[u8]) -> RnsPacketRef<'_> {
    RnsPacketRef {
        flags: header_2_flags(),
        hops: 9,
        transport_id: Some([0x22; 16]),
        destination_hash: RnsDestinationHash::new([0x33; 16]),
        context: RNS_CONTEXT_PATH_RESPONSE,
        data,
    }
}

const fn header_1_flags() -> RnsPacketFlags {
    RnsPacketFlags {
        header_type: RnsHeaderType::Header1,
        context_flag: false,
        transport_type: RnsTransportType::Broadcast,
        destination_type: RnsDestinationType::Single,
        packet_type: RnsPacketType::Data,
    }
}

const fn header_2_flags() -> RnsPacketFlags {
    RnsPacketFlags {
        header_type: RnsHeaderType::Header2,
        context_flag: true,
        transport_type: RnsTransportType::Transport,
        destination_type: RnsDestinationType::Group,
        packet_type: RnsPacketType::Announce,
    }
}
