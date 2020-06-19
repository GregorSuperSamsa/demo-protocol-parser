#include <stdio.h>
#include <stdint.h>
#include <string.h>


const uint16_t PACKET_PREAMBLE   = 0x4443;
// Minimum packet length: (2 * preamble_byte) + (1 * id_and_data_length_byte) + (1 * cs_byte)
const uint8_t  PACKET_LENGTH_MIN = 4;

typedef enum
{
    PARSE_OK = 0,
    PARSE_NOT_ENOUGH_DATA,
    PARSE_MESSAGE_EMPTY,
    PARSE_WRONG_HEADER,
    PARSE_WRONG_CHECKSUM
} ParseResult;

typedef struct
{
    ParseResult result;
    int identifier;
    int numDataBytes;
    char dataBytes[15];
} Protocol;

void protocolParse(const char* data, int numBytes, Protocol* pResult)
{
    // Internal enumeration, used to keep track of the current parse state
    typedef enum
    {
        STATE_PREAMBLE_0,
        STATE_PREAMBLE_1,
        STATE_ID_AND_DATA_LEN,
        STATE_DATA,
        STATE_CS,
        STATE_FINISHED,

    } ParseState;

    // CRITICAL: Pointer to the result structure is NULL
    if (!pResult) return;

    //
    if (!data || numBytes < PACKET_LENGTH_MIN)
    {
        pResult->result = PARSE_NOT_ENOUGH_DATA;
    }
    else
    {
        ParseState state = STATE_PREAMBLE_0;
        int start = 0;
        int offset = 0;

        while(offset < numBytes)
        {
            switch (state)
            {
            case STATE_PREAMBLE_0:
                if (data[offset] == (PACKET_PREAMBLE >> 8)) {
                    start = offset;
                    state = STATE_PREAMBLE_1;
                }
                break;
            case STATE_PREAMBLE_1:
                state = (data[offset] == (PACKET_PREAMBLE & 0xFF)) ? STATE_ID_AND_DATA_LEN : STATE_PREAMBLE_0;
                break;
            case STATE_ID_AND_DATA_LEN:
                pResult->identifier =   (uint8_t)(data[offset] & 0xF);
                pResult->numDataBytes = (uint8_t)((data[offset] >> 4) & 0xF);

                // Check whether packet data is less than expected
                // (Currently processed bytes) + (Data bytes) + (CS byte)
                if (numBytes >= (offset + 1 + pResult->numDataBytes + 1)) {
                    state = STATE_DATA;
                }
                else {
                    // Break while loop
                    offset = numBytes;
                }
                break;
            case STATE_DATA:
            {
                // Calculate available result data buffer length
                int buffer_len = sizeof (pResult->dataBytes) / sizeof (pResult->dataBytes[0]);

                // WARNING: Available result data buffer length is less than actual received data bytes
                if (buffer_len < pResult->numDataBytes) {
                    pResult->numDataBytes = buffer_len;
                }

                memcpy(pResult->dataBytes, &data[offset], pResult->numDataBytes);
                state = STATE_CS;

                // Move offset to CS byte index
                offset += pResult->numDataBytes;
                continue;
            }
            case STATE_CS:
            {
                // Calculate CS
                // NOTE: Using uint8_t for CS variable type would make mod 256 obsolete, as uint8_t would just overflow
                uint8_t cs = 0;
                for (int i = start; i < offset; i++) {
                    cs += data[i];
                }
                cs = cs % 256;

                if (cs == (uint8_t)data[offset]) {
                    state = STATE_FINISHED;
                }
                else {
                    // Break while loop
                    offset = numBytes;
                }
                break;
            }
            case STATE_FINISHED:
            default:
                // Break while loop
                offset = numBytes;
                break;
            }

            offset++;
        }

        // Set parse result, based on last parse state
        switch (state) {
        case STATE_PREAMBLE_0:
        case STATE_PREAMBLE_1:
            pResult->result = PARSE_WRONG_HEADER;
            break;
        case STATE_CS:
            pResult->result = PARSE_WRONG_CHECKSUM;
            break;
        case STATE_ID_AND_DATA_LEN:
        case STATE_DATA:
            pResult->result = PARSE_NOT_ENOUGH_DATA;
            break;
        case STATE_FINISHED:
            pResult->result = (pResult->numDataBytes > 0) ? PARSE_OK : PARSE_MESSAGE_EMPTY;
            break;
        default:
            break;
        }
    }
}


int main()
{
    Protocol p;
    char data[] = {0x44, 0x43, 0x44, 0x43, 0x3A, 0x11, 0x22, 0x33, 0x27};

    protocolParse(data, sizeof(data) / sizeof(data[0]), &p);

    return 0;
}
