/* SCM+ 915Mhz OOK
 *
 * 16 Bytes in total (decoded). OOK Modulation. Manchester on the whole packet. Hardcoded zerobit - the first bit is 0???
 * 
 * |      Field      | Length |  Value |                              Description                             |
 * |:---------------:|:------:|:------:|:--------------------------------------------------------------------:|
 * | Frame Sync      | 2      | 0x16A3 | 0001011010100011                                                     |
 * | ProtocolID      | 1      | 0x1E   | 00011110                                                             |
 * | Endpoint Type   | 1      |        | Least significant nibble is equivalent to SCM's endpoint type field. |
 * | Endpoint ID     | 4      |        | Verify by looking at your meter                                      |
 * | Consumption     | 4      |        | Total power(kwH?), water(gal or ccm), gas (ccm?)                     |
 * | Tamper          | 2      |        | I've only observed 0x4800 on water meters                            |
 * | Packet Checksum | 2      |        | CRC-16-CCITT of packet starting at Protocol ID.                      |
 * 
 * 
 * time      : 2023-01-20 19:45:09
 * model     : SCMplus      id        : 74047076
 * Protocol_ID: 0x1E        Endpoint_Type: 0xAB       Endpoint_ID: 74047076     Consumption: 122254
 * Tamper    : 0x4800       crc       : 0x776A        Meter_Type: Water         Integrity : CRC
 * *** Saving signal to file g014_915.2M_1000k.cu8 (50742 samples, 131072 bytes)
 * 1010101100110100110011001010110100101011010101001100110011001101001010101011001010110100110010110101001101010100101101001011001010101010101010101010101010101011010100110101001101001010110101001011001011001010101010101010101010110101001101010011010011001100xx
 * _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
 * time      : 2023-01-20 19:53:28
 * model     : SCMplus      id        : 74047076
 * Protocol_ID: 0x1E        Endpoint_Type: 0xAB       Endpoint_ID: 74047076     Consumption: 122255
 * Tamper    : 0x4800       crc       : 0x405A        Meter_Type: Water         Integrity : CRC
 * *** Saving signal to file g015_915.2M_1000k.cu8 (50743 samples, 131072 bytes)
 * x010101100110100110011001010110100101011010101001100110011001101001010101011001010110100110010110101001101010100101101001011001010101010101010101010101010101011010100110101001101001010110101010011001011001010101010101010101010110010101010101011001101001100xx
 * 
 * 
 * */
#include "../app.h"
#include "limits.h"

#define USE_TEST_VECTOR 0

//#define SIZEOF_MEMBER(struct, member) sizeof(((struct*)nullptr)->member)
// For convenience, struct is not properly utilized or init but remains as a helpful reference
typedef struct SCM_PLUS_MESSAGE_ {
    uint16_t FrameSync;
    uint8_t ProtocolID;
    uint8_t EndpointType;
    uint32_t EndpointID;
    uint32_t Consumption;
    uint16_t Tamper;
    uint16_t PacketCRC;
} SCM_PLUS_MESSAGE;

const uint8_t FRAME_SYNC_LENGTH = 2; // bytes
const uint8_t MANCHESTER_FACTOR = 2; // each bit is encoded in 2 symbols
// 16 bytes, manchester encoded 16*8*2=256
const uint16_t BITS_IN_MESSAGE = (sizeof(SCM_PLUS_MESSAGE) * CHAR_BIT) * MANCHESTER_FACTOR;
const uint8_t MESSAGE_SIZE = sizeof(SCM_PLUS_MESSAGE) - FRAME_SYNC_LENGTH; // 14
const uint8_t CHECKSUM_SIZE = 2; // bytes
const uint8_t CHECKSUM_DATA_SIZE = MESSAGE_SIZE - CHECKSUM_SIZE;
const uint16_t SCM_CRC_POLY = 0x1021;
const uint16_t SCM_CRC_INIT = 0x0971;

static const char* test_vector =
    "000000000000000000101010110011010011001100101011010010101101010100110011001100110100101010101100101011010011001011010100110101010010110100101100101010101010101010101010101010101101010011010100110100101011010010101100101100101010101010101010101010101101001011001010101100110011111";
// "101010110011010011001100101011010010101101010100110011001100110100101010101100101011010011001011010100110101010010110100101100101010101010101010101010101010101101010011010100110100101011010100101100101100101010101010101010101011010100110101001101001100110011111";
// "1010101100110100110011001010110100101011010101001100110011001101001010101011001010110100110010110101001101010100101101001011001010101010101010101010101010101011010100110101001101001010101010101011001011001010101010101010101010110100110100101011010011001101 ";

static bool decode(uint8_t* bits, uint32_t numbytes, uint32_t numbits, ProtoViewMsgInfo* info) {
    if(USE_TEST_VECTOR) { /* Test vector to check that decoding works. */
        bitmap_set_pattern(bits, strlen(test_vector) * CHAR_BIT, 0, test_vector);
        numbits = strlen(test_vector);
    }

    if(numbits < BITS_IN_MESSAGE) {
        FURI_LOG_E(TAG, "SCM+ not enough bits %lu", numbits);
        return false;
    }

    const char* sync_pattern =
        "01010110011010011001100101011010"; // -> 0001011010100011 manchester II encoded (URH)

    uint64_t off = bitmap_seek_bits(
        bits,
        numbits / CHAR_BIT /* todo: should be numbytes but im testing */,
        0,
        numbits,
        sync_pattern);

    if(off == BITMAP_SEEK_NOT_FOUND) {
        FURI_LOG_E(TAG, "SCM+ preamble not found");
        return false;
    }

    info->start_off = off;
    off += 2 * CHAR_BIT * MANCHESTER_FACTOR; /* Skip sync 2 bytes, Manchester encoded*/

    uint8_t raw[MESSAGE_SIZE];
    uint32_t decoded = convert_from_line_code(raw, MESSAGE_SIZE, bits, numbytes, off, "01", "10");

    // FURI_LOG_E(TAG, "SCM+ raw   %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", raw[0], // ProtocolID raw[1], // EndpointType raw[2], // EndpointID raw[3], // EndpointID raw[4], // EndpointID raw[5], // EndpointID raw[6], // Consumption raw[7], // Consumption raw[8], // Consumption raw[9], // Consumption raw[10], // Tamper raw[11], // Tamper raw[12], // CRC raw[13]); // CRC

    if(decoded < CHAR_BIT * MESSAGE_SIZE) {
        FURI_LOG_E(TAG, "SCM+ not enough bits decoded %lu, exiting", decoded);
        return false; /* Require the full 14 remaining bytes after sync */
    }

    info->pulses_count = (off + MESSAGE_SIZE * MANCHESTER_FACTOR * CHAR_BIT) - info->start_off;

    // FURI_LOG_E(
    //     TAG, "SCM+ start_offset %lu, pulses_count %lu", info->start_off, info->pulses_count);

    uint16_t crc, pkt_checksum;
    crc = crc16(raw, CHECKSUM_DATA_SIZE, SCM_CRC_INIT, SCM_CRC_POLY);
    pkt_checksum = (raw[12] << 8 | raw[13]);

    if(crc != pkt_checksum) {
        // FURI_LOG_E(TAG, "SCM+ crc16 MISMATCH. checksum: %u 0x%04X  |   crc: %u 0x%04X", pkt_checksum, pkt_checksum, crc, crc);
        return false;
    }

    uint32_t endpoint_id = ((uint32_t)raw[2] << 24) | (raw[3] << 16) | (raw[4] << 8) | (raw[5]);
    uint32_t consumption_data = ((uint32_t)raw[6] << 24) | (raw[7] << 16) | (raw[8] << 8) |
                                (raw[9]);
    uint16_t physical_tamper = (raw[10] << 8 | raw[11]);

    // Least significant nibble of endpoint_type is equivalent to SCM's endpoint type field
    // id info from https://github.com/bemasher/rtlamr/wiki/Compatible-Meters
    char* meter_type;
    switch(raw[1] & 0x0f) {
    case 4:
    case 5:
    case 7:
    case 8:
        meter_type = "Electric";
        break;
    case 0:
    case 1:
    case 2:
    case 9:
    case 12:
        meter_type = "Gas";
        break;
    case 3:
    case 11:
    case 13:
        meter_type = "Water";
        break;
    default:
        meter_type = "unknown";
        break;
    }

    fieldset_add_bytes(info->fieldset, "raw", raw, 14 * 2);
    fieldset_add_str(info->fieldset, "type", meter_type, 10);
    fieldset_add_int(info->fieldset, "id", endpoint_id, 32);
    fieldset_add_int(info->fieldset, "consumption", consumption_data, 4 * 2);
    fieldset_add_hex(info->fieldset, "tamper", physical_tamper, 4 * 2);
    fieldset_add_hex(info->fieldset, "crc", crc, 16);
    return true;
}

/* Give fields and defaults for the signal creator. */
static void get_fields(ProtoViewFieldSet* fieldset) {
    uint8_t protocol_id[1] = {0x1E};
    uint8_t endpoint_type[1] = {0xAB};
    uint8_t tamper[2] = {0x48, 0x00};

    fieldset_add_bytes(fieldset, "Protocol ID", protocol_id, 1 * 2);
    fieldset_add_bytes(
        fieldset, "Endpoint Type", endpoint_type, 1 * 2); // water=AB, electric=04, gas=?
    fieldset_add_int(fieldset, "Endpoint ID", 42069, 32);
    fieldset_add_int(fieldset, "Consumption", 420, 32);
    fieldset_add_bytes(fieldset, "Tamper", tamper, 2 * 2);
}

/* Create a SCM+ signal, according to the fields provided. */
static void build_message(RawSamplesBuffer* samples, ProtoViewFieldSet* fieldset) {
    uint32_t te = 30; // Short pulse duration in microseconds.

    // Preamble/sync
    const char* psync = "01010110011010011001100101011010";
    const char* p = psync;
    while(*p) {
        raw_samples_add_or_update(samples, *p == '1', te);
        p++;
    }

    // Data, 14 bytes
    uint8_t data[14];

    data[0] = fieldset->fields[0]->uvalue; // Protocol ID
    data[1] = fieldset->fields[1]->bytes[0]; // Endpoint type
    data[2] = fieldset->fields[2]->bytes[0]; // Endpoint ID
    data[3] = fieldset->fields[2]->bytes[1]; // EndpointID
    data[4] = fieldset->fields[2]->bytes[2]; // EndpointID
    data[5] = fieldset->fields[2]->bytes[3]; // EndpointID
    data[6] = fieldset->fields[3]->bytes[0]; // consumption
    data[7] = fieldset->fields[3]->bytes[1]; // consumption
    data[8] = fieldset->fields[3]->bytes[2]; // consumption
    data[9] = fieldset->fields[3]->bytes[3]; // consumption
    data[10] = fieldset->fields[4]->bytes[0]; // tamper
    data[11] = fieldset->fields[4]->bytes[1]; // tamper
    uint16_t crc_result = crc16(data, 12, SCM_CRC_INIT, SCM_CRC_POLY);
    data[12] = (crc_result >> 8) & 0xFF; // upper byte
    data[13] = crc_result & 0xFF; // lower byte

    // Generate Manchester code for each bit
    for(uint32_t j = 0; j < MESSAGE_SIZE * 8; j++) {
        if(bitmap_get(data, sizeof(data), j)) {
            raw_samples_add_or_update(samples, true, te);
            raw_samples_add_or_update(samples, false, te);
        } else {
            raw_samples_add_or_update(samples, false, te);
            raw_samples_add_or_update(samples, true, te);
        }
    }
}

ProtoViewDecoder ScmPlusDecoder = {
    .name = "SCM+ ERT",
    .decode = decode,
    .get_fields = get_fields,
    .build_message = build_message};
