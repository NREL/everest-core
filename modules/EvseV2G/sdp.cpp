// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2022-2023 chargebyte GmbH
// Copyright (C) 2022-2023 Contributors to EVerest
#include "sdp.hpp"
#include "log.hpp"
extern "C" {
    #include "asn1/all_asn1c_headers.h"
}
//#include "all_asn1c_headers.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DEBUG 1

/* defines for V2G SDP implementation */
#define SDP_SRV_PORT 15118 // Regular port defined in DIN SPEC 70121 [V2G-DC-159] and ISO 15118-02 [V2G2-125/205] for SDP Server
#define ESDP_SRV_PORT 15200 // As per [V2G200-51-1/2] in ISO/PAS CD 15118-200:2024(E) - STANDARD NOT YET PUBLISHED

#define SDP_VERSION         0x01
#define SDP_INVERSE_VERSION 0xfe

#define SDP_HEADER_LEN           8 // Header length is the same for SDP and ESDP as per [V2G200-4-1] in ISO/PAS CD 15118-200:2024(E)
#define SDP_REQUEST_PAYLOAD_LEN  2
#define SDP_RESPONSE_PAYLOAD_LEN 20

// Define ESDP Req & Res payload lengths for ESDP (Subject to change)
#define MAX_ESDP_REQUEST_PAYLOAD_LEN 512
#define MAX_ESDP_RESPONSE_PAYLOAD_LEN 512

// Assign regular SDP Payload types as per DIN 70121 [V2G2-DC-194/208] & ISO 15118-02 [V2G2-140/152]
#define SDP_REQUEST_TYPE  0x9000
#define SDP_RESPONSE_TYPE 0x9001

// Assign ESDP Payload types as per [V2G200-41-1] in ISO/PAS CD 15118-200:2024(E) - STANDARD NOT YET PUBLISHED
#define ESDP_REQUEST_TYPE  0x2000 
#define ESDP_RESPONSE_TYPE 0x2000

// Define ESDP Version for verification as per [V2G200-52-2] in ISO/PAS CD 15118-200:2024(E)
#define ESDP_VERSION        0x0100

// Define Maximum V2GTP Paylod Size as per [V2G200-52-3] in ISO/PAS CD 15118-200:2024(E)
#define ESDP_MAX_V2GTP_PAYLOAD_SIZE 0x1000

#define POLL_TIMEOUT 20

enum sdp_security {
    SDP_SECURITY_TLS = 0x00,
    SDP_SECURITY_NONE = 0x10,
};

enum sdp_transport_protocol {
    SDP_TRANSPORT_PROTOCOL_TCP = 0x00,
    SDP_TRANSPORT_PROTOCOL_UDP = 0x10,
};

/* link-local multicast address ff02::1 aka ip6-allnodes */
#define IN6ADDR_ALLNODES                                                                                               \
    { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }

/* bundles various aspects of a SDP query */
struct sdp_query {
    struct v2g_context* v2g_ctx;

    struct sockaddr_in6 remote_addr;

    enum sdp_security security_requested;
    enum sdp_transport_protocol proto_requested;
};

/*
 * Fills the SDP header into a given buffer. Same function for both SDP and ESDP
 * since the header length is the same for both
 */
static int sdp_write_header(uint8_t* buffer, uint16_t payload_type, uint32_t payload_len) {
    int offset = 0;

    buffer[offset++] = SDP_VERSION;
    buffer[offset++] = SDP_INVERSE_VERSION;

    /* payload is network byte order */
    buffer[offset++] = (payload_type >> 8) & 0xff;
    buffer[offset++] = payload_type & 0xff;

    /* payload_length is network byte order */
    buffer[offset++] = (payload_len >> 24) & 0xff;
    buffer[offset++] = (payload_len >> 16) & 0xff;
    buffer[offset++] = (payload_len >> 8) & 0xff;
    buffer[offset++] = payload_len & 0xff;

    return offset;
}

static int sdp_validate_header(uint8_t* buffer, uint16_t expected_payload_type, uint32_t expected_payload_len) {
    uint16_t payload_type;
    uint32_t payload_len;

    if (buffer[0] != SDP_VERSION) {
        dlog(DLOG_LEVEL_ERROR, "Invalid SDP version");
        return -1;
    }

    if (buffer[1] != SDP_INVERSE_VERSION) {
        dlog(DLOG_LEVEL_ERROR, "Invalid SDP inverse version");
        return -1;
    }

    payload_type = (buffer[2] << 8) + buffer[3];
    if (payload_type != expected_payload_type) {
        dlog(DLOG_LEVEL_ERROR, "Invalid payload type: expected %" PRIu16 ", received %" PRIu16, expected_payload_type,
             payload_type);
        return -1;
    }

    payload_len = (buffer[4] << 24) + (buffer[5] << 16) + (buffer[6] << 8) + buffer[7];
    if (payload_len != expected_payload_len) {
        dlog(DLOG_LEVEL_ERROR, "Invalid payload length: expected %" PRIu32 ", received %" PRIu32, expected_payload_len,
             payload_len);
        return -1;
    }

    return 0;
}

static int esdp_validate_header(uint8_t* buffer, uint16_t expected_payload_type, uint32_t max_esdp_payload_len, uint16_t expected_esdp_version) {
    /* Returns -1 for invalid V2GTP header, 1 for invalid ESDP Header (version, max payload size), and 0 otherwise*/

    uint16_t payload_type;
    uint32_t payload_len;
    uint16_t esdp_version;

    if (buffer[0] != SDP_VERSION) {
        dlog(DLOG_LEVEL_ERROR, "Invalid SDP version in header of ESDP packet");
        return -1;
    }

    if (buffer[1] != SDP_INVERSE_VERSION) {
        dlog(DLOG_LEVEL_ERROR, "Invalid SDP inverse version in header of ESDP packet");
        return -1;
    }

    payload_type = (buffer[2] << 8) + buffer[3];
    if (payload_type != expected_payload_type) {
        dlog(DLOG_LEVEL_ERROR, "Invalid payload type: expected %" PRIu16 ", received %" PRIu16 " in header of ESDP packet",
             expected_payload_type, payload_type);
        return -1;
    }

    payload_len = (buffer[4] << 24) + (buffer[5] << 16) + (buffer[6] << 8) + buffer[7];
    if (payload_len >= max_esdp_payload_len) {
        dlog(DLOG_LEVEL_ERROR, "Size of ESDPReq payload exceeds max limit. ESDPReq payload is %" PRIu32 " bytes while max limit is %" PRIu32 " bytes",
             payload_len, max_esdp_payload_len);
        return 1;
    }
    
    /* Verify ESDP version as per [V2G200-52-2] in ISO/PAS CD 15118-200:2024(E). Added for ESDP */
    esdp_version = (buffer[8] << 8) + buffer[9];    
    if (esdp_version != expected_esdp_version) {
    	dlog(DLOG_LEVEL_ERROR, "Unsupported ESDP Version: expected %" PRIu16 ", received %" PRIu16 " in ESDP Payload",
    	     expected_esdp_version, esdp_version);
     	dlog(DLOG_LEVEL_ERROR, "The last ESDP packet will be discarded since the ESDP version is unsupported");
     	return 1;
    } else {
        dlog(DLOG_LEVEL_INFO, "EVCC's reported ESDP Version: %" PRIu16, esdp_version);
    }
    
    return 0;
}

int sdp_create_response(uint8_t* buffer, struct sockaddr_in6* addr, enum sdp_security security,
                        enum sdp_transport_protocol proto) {
    int offset = SDP_HEADER_LEN;

    /* fill in first the payload */

    /* address is already network byte order */
    memcpy(&buffer[offset], &addr->sin6_addr, sizeof(addr->sin6_addr));
    offset += sizeof(addr->sin6_addr);

    memcpy(&buffer[offset], &addr->sin6_port, sizeof(addr->sin6_port));
    offset += sizeof(addr->sin6_port);

    buffer[offset++] = security;
    buffer[offset++] = proto;

    /* now fill in the header with payload length */
    sdp_write_header(buffer, SDP_RESPONSE_TYPE, offset - SDP_HEADER_LEN);

    return offset;
}

int encode_ESDPRes_Extensions(uint8_t* buffer_esdp, int offset, struct sockaddr_in6* addr, enum sdp_security security) {
    /* Create and populate Extensions */
    Extensions_t *extensions = (Extensions_t *)calloc(1, sizeof(Extensions_t));
    if (!extensions) {
        dlog(DLOG_LEVEL_ERROR, "Failed to allocate memory for extensions");
    }

    /* ExtensionID 1 - Charging interface extension */
    /* Using placeholder value corresponding to CCS1 for charging interface */
    /* All enumerations can be found in asn1/ChargingInterface.h */
    StandardizedExtension_t *charging_interface_ext = (StandardizedExtension_t *)calloc(1, sizeof(StandardizedExtension_t));
    if (!charging_interface_ext) {
        dlog(DLOG_LEVEL_ERROR, "Failed to allocate memory for Charging Interface Extension");
    }
    charging_interface_ext -> extensionID = 1;
    ChargingInterface_t charging_interface = ChargingInterface_ccs1;
    uint8_t *ci_buffer = (uint8_t *)calloc(128, sizeof(uint8_t));
    asn_enc_rval_t ci_enc_rval = der_encode_to_buffer(&asn_DEF_ChargingInterface, &charging_interface,
                    ci_buffer, 128);
    //dlog(DLOG_LEVEL_INFO, "ChargingInterface data encoded: %zu bytes\n", ci_enc_rval.encoded);
    OCTET_STRING_fromBuf(&charging_interface_ext -> extensionValue, (char *)ci_buffer, ci_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, charging_interface_ext);
    free(ci_buffer);

    /* ExtensionID 2 - Basic signaling extension */
    /* Using a placeholder list including all Protocols defined in ISO/PAS CD 15118-200:2024(E) */
    StandardizedExtension_t *basic_signaling_ext = (StandardizedExtension_t *)calloc(1, sizeof(StandardizedExtension_t));
    basic_signaling_ext -> extensionID = 2;
    BasicSignaling_t *basic_signaling = (BasicSignaling_t *)calloc(1, sizeof(BasicSignaling_t));
    BasicSignalingProtocol_t *protocol01 = (BasicSignalingProtocol_t *)calloc(1, sizeof(BasicSignalingProtocol_t));
    BasicSignalingProtocol_t *protocol02 = (BasicSignalingProtocol_t *)calloc(1, sizeof(BasicSignalingProtocol_t));
    BasicSignalingProtocol_t *protocol03 = (BasicSignalingProtocol_t *)calloc(1, sizeof(BasicSignalingProtocol_t));
    BasicSignalingProtocol_t *protocol04 = (BasicSignalingProtocol_t *)calloc(1, sizeof(BasicSignalingProtocol_t));
    *protocol01 = BasicSignalingProtocol_iec61851_1_ED2;
    *protocol02 = BasicSignalingProtocol_iec61851_1_ED3;
    *protocol03 = BasicSignalingProtocol_iec61851_23_ED1;
    *protocol04 = BasicSignalingProtocol_iec61851_23_ED2;
    ASN_SEQUENCE_ADD(&basic_signaling -> list, protocol01);
    ASN_SEQUENCE_ADD(&basic_signaling -> list, protocol02);
    ASN_SEQUENCE_ADD(&basic_signaling -> list, protocol03);
    ASN_SEQUENCE_ADD(&basic_signaling -> list, protocol04);       
    uint8_t *bs_buffer = (uint8_t *)calloc(128, sizeof(uint8_t));
    asn_enc_rval_t bs_enc_rval = der_encode_to_buffer(&asn_DEF_BasicSignaling, basic_signaling, bs_buffer, 128);
    //dlog(DLOG_LEVEL_INFO, "Basic Signaling data encoded: %zu bytes\n", bs_enc_rval.encoded);
    OCTET_STRING_fromBuf(&basic_signaling_ext -> extensionValue, (char *)bs_buffer, bs_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, basic_signaling_ext);
    free(bs_buffer);

    /* ExtensionID 3 - IPv6 Socket extension */
    StandardizedExtension_t *ipv6_socket_ext = (StandardizedExtension_t *)calloc(1, sizeof(StandardizedExtension_t));
    ipv6_socket_ext -> extensionID = 3;
    IPv6Socket_t *ipv6_socket = (IPv6Socket_t *)calloc(1, sizeof(IPv6Socket_t));
    uint8_t ipv6_secc_address[sizeof(addr -> sin6_addr)] = {0};
    uint8_t ipv6_secc_port[4] = {0};
    memcpy(&ipv6_secc_address[0], &addr->sin6_addr, sizeof(addr->sin6_addr));
    memcpy(&ipv6_secc_port[2], &addr->sin6_port, sizeof(addr->sin6_port));
    OCTET_STRING_fromBuf(&ipv6_socket -> ipv6Address, (const char *)&ipv6_secc_address, sizeof(ipv6_secc_address));
    OCTET_STRING_fromBuf(&ipv6_socket -> tcpPort, (const char *)&ipv6_secc_port, sizeof(ipv6_secc_port));
    uint8_t *ip_buffer = (uint8_t *)calloc(128, sizeof(uint8_t));
    asn_enc_rval_t ip_enc_rval = der_encode_to_buffer(&asn_DEF_IPv6Socket, ipv6_socket, ip_buffer, 128);
    //dlog(DLOG_LEVEL_INFO, "IPv6 Socket data encoded: %zu bytes\n", ip_enc_rval.encoded);
    OCTET_STRING_fromBuf(&ipv6_socket_ext -> extensionValue, (char *)ip_buffer, ip_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, ipv6_socket_ext);
    free(ip_buffer);

    /* Placeholder switch block. Can be used to selectively encode HLC Extension */
    /* switch (security) {
        case SDP_SECURITY_TLS:
            sec_profile01 -> securityProfile = SecurityProfile_tls12_server;
        case SDP_SECURITY_NONE:
            sec_profile01 -> securityProfile = SecurityProfile_tcpOnly;
            break;
        default:
            dlog(DLOG_LEVEL_ERROR, "Unknown Security. Unable to encode correct security into ESDPResponse's HLC extension");
            break:
    } */

    /* ExtensionID 4 - High Level Communication extension */
    /* Using a placeholder list of all possible combinations for now. Use the switch block above to selectively encode supported HLC Extensions.
        Then remove unsupported combinations in the future */
    StandardizedExtension_t *hlc_ext = (StandardizedExtension_t *)calloc(1, sizeof(StandardizedExtension_t));
    hlc_ext -> extensionID = 4;
    HighLevelCommunication_t *hlc = (HighLevelCommunication_t *)calloc(1, sizeof(HighLevelCommunication_t));

    /* First HLC Tuple - For DIN 70121:2014 (TCP with EIM with DC) */
    HighLevelCommunicationTuple_t *hlc_tuple01 = (HighLevelCommunicationTuple_t *)calloc(1, sizeof(HighLevelCommunicationTuple_t));
    hlc_tuple01 -> hlcProtocol = HLCProtocol_din_spec_70121_2014;
    SecurityProfileTuple_t *sec_profile01 = (SecurityProfileTuple_t *)calloc(1, sizeof(SecurityProfileTuple_t));
    sec_profile01 -> securityProfile = SecurityProfile_tcpOnly;
    AuthorizationMethod_t *auth01 = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
    *auth01 = AuthorizationMethod_eim;
    EnergyTransferMode_t *mode01 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode01 = EnergyTransferMode_dc;
    ASN_SEQUENCE_ADD(&sec_profile01 -> authorizationMethod.list, auth01);
    ASN_SEQUENCE_ADD(&sec_profile01 -> energyTransferMode.list, mode01);
    ASN_SEQUENCE_ADD(&hlc_tuple01 -> securityProfileTuple.list, sec_profile01);
    ASN_SEQUENCE_ADD(&hlc -> list, hlc_tuple01);

    /* Second HLC Tuple - For ISO 15118-2:2014 (TCP with EIM with dc & ac) */
    HighLevelCommunicationTuple_t *hlc_tuple02 = (HighLevelCommunicationTuple_t *)calloc(1, sizeof(HighLevelCommunicationTuple_t));
    hlc_tuple02 -> hlcProtocol = HLCProtocol_iso_15118_2_2014;
    SecurityProfileTuple_t *sec_profile02_01 = (SecurityProfileTuple_t *)calloc(1, sizeof(SecurityProfileTuple_t));
    sec_profile02_01 -> securityProfile = SecurityProfile_tcpOnly;
    AuthorizationMethod_t *auth02_01 = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
    *auth02_01 = AuthorizationMethod_eim;
    EnergyTransferMode_t *mode02_01_01 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode02_01_01 = EnergyTransferMode_dc;
    EnergyTransferMode_t *mode02_01_02 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode02_01_02 = EnergyTransferMode_ac;
    ASN_SEQUENCE_ADD(&sec_profile02_01 -> authorizationMethod.list, auth02_01);
    ASN_SEQUENCE_ADD(&sec_profile02_01 -> energyTransferMode.list, mode02_01_01);
    ASN_SEQUENCE_ADD(&sec_profile02_01 -> energyTransferMode.list, mode02_01_02);
    
    /* and (TLS12_server with EIM & PNC_2 with dc & ac) */
    SecurityProfileTuple_t *sec_profile02_02 = (SecurityProfileTuple_t *)calloc(1, sizeof(SecurityProfileTuple_t));
    sec_profile02_02 -> securityProfile = SecurityProfile_tls12_server;
    AuthorizationMethod_t *auth02_02_01 = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
    *auth02_02_01 = AuthorizationMethod_eim;
    AuthorizationMethod_t *auth02_02_02 = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
    *auth02_02_02 = AuthorizationMethod_pnc_2;
    EnergyTransferMode_t *mode02_02_01 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode02_02_01 = EnergyTransferMode_dc;
    EnergyTransferMode_t *mode02_02_02 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode02_02_02 = EnergyTransferMode_ac;
    ASN_SEQUENCE_ADD(&sec_profile02_02 -> authorizationMethod.list, auth02_02_01);
    ASN_SEQUENCE_ADD(&sec_profile02_02 -> authorizationMethod.list, auth02_02_02);
    ASN_SEQUENCE_ADD(&sec_profile02_02 -> energyTransferMode.list, mode02_02_01);
    ASN_SEQUENCE_ADD(&sec_profile02_02 -> energyTransferMode.list, mode02_02_02);  
    ASN_SEQUENCE_ADD(&hlc_tuple02 -> securityProfileTuple.list, sec_profile02_01);
    ASN_SEQUENCE_ADD(&hlc_tuple02 -> securityProfileTuple.list, sec_profile02_02);
    ASN_SEQUENCE_ADD(&hlc -> list, hlc_tuple02);

    /* Third HLC Tuple - For ISO 15118-20:2022 (TCP with EIM with dc & dc-bpt & ac & ac-bpt) */
    HighLevelCommunicationTuple_t *hlc_tuple03 = (HighLevelCommunicationTuple_t *)calloc(1, sizeof(HighLevelCommunicationTuple_t));
    hlc_tuple03 -> hlcProtocol = HLCProtocol_iso_15118_20_2022;
    SecurityProfileTuple_t *sec_profile03_01 = (SecurityProfileTuple_t *)calloc(1, sizeof(SecurityProfileTuple_t));
    sec_profile03_01 -> securityProfile = SecurityProfile_tcpOnly;
    AuthorizationMethod_t *auth03_01 = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
    *auth03_01 = AuthorizationMethod_eim;
    EnergyTransferMode_t *mode03_01_01 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_01_01 = EnergyTransferMode_dc;
    EnergyTransferMode_t *mode03_01_02 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_01_02 = EnergyTransferMode_dc_bpt;    
    EnergyTransferMode_t *mode03_01_03 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_01_03 = EnergyTransferMode_ac;
    EnergyTransferMode_t *mode03_01_04 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_01_04 = EnergyTransferMode_ac_bpt;    
    ASN_SEQUENCE_ADD(&sec_profile03_01 -> authorizationMethod.list, auth03_01);
    ASN_SEQUENCE_ADD(&sec_profile03_01 -> energyTransferMode.list, mode03_01_01);
    ASN_SEQUENCE_ADD(&sec_profile03_01 -> energyTransferMode.list, mode03_01_02);
    ASN_SEQUENCE_ADD(&sec_profile03_01 -> energyTransferMode.list, mode03_01_03);
    ASN_SEQUENCE_ADD(&sec_profile03_01 -> energyTransferMode.list, mode03_01_04);

    /* and (TLS12_server with EIM & PNC_2 with dc & dc-bpt & ac & ac-bpt) */
    SecurityProfileTuple_t *sec_profile03_02 = (SecurityProfileTuple_t *)calloc(1, sizeof(SecurityProfileTuple_t));
    sec_profile03_02 -> securityProfile = SecurityProfile_tls12_server;
    AuthorizationMethod_t *auth03_02_01 = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
    *auth03_02_01 = AuthorizationMethod_eim;
    AuthorizationMethod_t *auth03_02_02 = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
    *auth03_02_02 = AuthorizationMethod_pnc_2;
    EnergyTransferMode_t *mode03_02_01 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_02_01 = EnergyTransferMode_dc;
    EnergyTransferMode_t *mode03_02_02 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_02_02 = EnergyTransferMode_dc_bpt;    
    EnergyTransferMode_t *mode03_02_03 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_02_03 = EnergyTransferMode_ac;
    EnergyTransferMode_t *mode03_02_04 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_02_04 = EnergyTransferMode_ac_bpt;
    ASN_SEQUENCE_ADD(&sec_profile03_02 -> authorizationMethod.list, auth03_02_01);
    ASN_SEQUENCE_ADD(&sec_profile03_02 -> authorizationMethod.list, auth03_02_02);
    ASN_SEQUENCE_ADD(&sec_profile03_02 -> energyTransferMode.list, mode03_02_01);
    ASN_SEQUENCE_ADD(&sec_profile03_02 -> energyTransferMode.list, mode03_02_02);
    ASN_SEQUENCE_ADD(&sec_profile03_02 -> energyTransferMode.list, mode03_02_03);
    ASN_SEQUENCE_ADD(&sec_profile03_02 -> energyTransferMode.list, mode03_02_04);
    
    /* and (TLS13_mutual with EIM & PNC_2 & PNC_20 with dc & dc-bpt & ac & ac-bpt) */
    SecurityProfileTuple_t *sec_profile03_03 = (SecurityProfileTuple_t *)calloc(1, sizeof(SecurityProfileTuple_t));
    sec_profile03_03 -> securityProfile = SecurityProfile_tls13_mutual;
    AuthorizationMethod_t *auth03_03_01 = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
    *auth03_03_01 = AuthorizationMethod_eim;
    AuthorizationMethod_t *auth03_03_02 = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
    *auth03_03_02 = AuthorizationMethod_pnc_2;
    AuthorizationMethod_t *auth03_03_03 = (AuthorizationMethod_t *)calloc(1, sizeof(AuthorizationMethod_t));
    *auth03_03_03 = AuthorizationMethod_pnc_20;    
    EnergyTransferMode_t *mode03_03_01 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_03_01 = EnergyTransferMode_dc;
    EnergyTransferMode_t *mode03_03_02 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_03_02 = EnergyTransferMode_dc_bpt;    
    EnergyTransferMode_t *mode03_03_03 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_03_03 = EnergyTransferMode_ac;
    EnergyTransferMode_t *mode03_03_04 = (EnergyTransferMode_t *)calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_03_04 = EnergyTransferMode_ac_bpt;
    ASN_SEQUENCE_ADD(&sec_profile03_03 -> authorizationMethod.list, auth03_03_01);
    ASN_SEQUENCE_ADD(&sec_profile03_03 -> authorizationMethod.list, auth03_03_02);
    ASN_SEQUENCE_ADD(&sec_profile03_03 -> authorizationMethod.list, auth03_03_03);    
    ASN_SEQUENCE_ADD(&sec_profile03_03 -> energyTransferMode.list, mode03_03_01);
    ASN_SEQUENCE_ADD(&sec_profile03_03 -> energyTransferMode.list, mode03_03_02);
    ASN_SEQUENCE_ADD(&sec_profile03_03 -> energyTransferMode.list, mode03_03_03);
    ASN_SEQUENCE_ADD(&sec_profile03_03 -> energyTransferMode.list, mode03_03_04);
    ASN_SEQUENCE_ADD(&hlc_tuple03 -> securityProfileTuple.list, sec_profile03_01);
    ASN_SEQUENCE_ADD(&hlc_tuple03 -> securityProfileTuple.list, sec_profile03_02);
    ASN_SEQUENCE_ADD(&hlc_tuple03 -> securityProfileTuple.list, sec_profile03_03);
    ASN_SEQUENCE_ADD(&hlc -> list, hlc_tuple03);
    
    /* Add hlc sequence of hlc_tuples to extensions -> extensionValue and standardized extension */
    uint8_t *hlc_buffer = (uint8_t *)calloc(256, sizeof(uint8_t));
    asn_enc_rval_t hlc_enc_rval = der_encode_to_buffer(&asn_DEF_HighLevelCommunication, hlc, hlc_buffer, 256);
    //dlog(DLOG_LEVEL_INFO, "HLC data encoded: %zu bytes\n", hlc_enc_rval.encoded);
    OCTET_STRING_fromBuf(&hlc_ext -> extensionValue, (char *)hlc_buffer, hlc_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, hlc_ext);
    free(hlc_buffer);

    /* ExtensionID 5 - EMSP identifiers extension */
    /* Using placeholder EMSP values for now */
    /* Be sure to order EMSPIdentifiers list based on priority per [V2G200-542-3] in ISO/PAS CD 15118-200:2024(E) - STANDARD NOT YET PUBLISHED */
    StandardizedExtension_t *emsp_ids_ext = (StandardizedExtension_t *)calloc(1, sizeof(StandardizedExtension_t));
    emsp_ids_ext -> extensionID = 5;
    EMSPIdentifiers_t *emsp_ids = (EMSPIdentifiers_t *)calloc(1, sizeof(EMSPIdentifiers_t));
    EMSPIdentifier_t *emsp_id01 = (EMSPIdentifier_t *)calloc(1, sizeof(EMSPIdentifier_t));
    OCTET_STRING_fromBuf(emsp_id01, "EMSP_1", strlen("EMSP_1"));
    ASN_SEQUENCE_ADD(&emsp_ids -> list, emsp_id01);
    EMSPIdentifier_t *emsp_id02 = (EMSPIdentifier_t *)calloc(1, sizeof(EMSPIdentifier_t));
    OCTET_STRING_fromBuf(emsp_id02, "EMSP_2", strlen("EMSP_2"));
    ASN_SEQUENCE_ADD(&emsp_ids -> list, emsp_id02);
    uint8_t *emsp_buffer = (uint8_t *)calloc(128, sizeof(uint8_t));
    asn_enc_rval_t emsp_enc_rval = der_encode_to_buffer(&asn_DEF_EMSPIdentifiers, emsp_ids, emsp_buffer, 128);
    //dlog(DLOG_LEVEL_INFO, "EMSP Identifiers data encoded: %zu bytes\n", emsp_enc_rval.encoded);
    OCTET_STRING_fromBuf(&emsp_ids_ext -> extensionValue, (char *)emsp_buffer, emsp_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, emsp_ids_ext);
    free(emsp_buffer);

    /* ExtensionID 6 - DC charging limits extension */
    /* Using placeholder values for Maximum and Minimum voltage limits */
    StandardizedExtension_t *dc_limits_ext = (StandardizedExtension_t *)calloc(1, sizeof(StandardizedExtension_t));
    dc_limits_ext -> extensionID = 6;
    DCChargingLimits_t *dc_limits = (DCChargingLimits_t *)calloc(1, sizeof(DCChargingLimits_t));
    dc_limits -> maximumVoltage = 1000;
    dc_limits -> minimumVoltage = 250;
    uint8_t *dc_limits_buffer = (uint8_t *)calloc(128, sizeof(uint8_t));
    asn_enc_rval_t dc_limits_enc_rval = der_encode_to_buffer(&asn_DEF_DCChargingLimits, dc_limits, dc_limits_buffer, 128);
    //dlog(DLOG_LEVEL_INFO, "DC Charging Limits data encoded: %zu bytes\n", dc_limits_enc_rval.encoded);
    OCTET_STRING_fromBuf(&dc_limits_ext -> extensionValue, (char *)dc_limits_buffer, dc_limits_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, dc_limits_ext);
    free(dc_limits_buffer);

    /* ExtensionID 7 - Conductive Charging Interface Limitations extension */
    /* Using placeholder values for Maximum contactor temperature */
    StandardizedExtension_t *chrg_int_limits_ext = (StandardizedExtension_t *)calloc(1, sizeof(StandardizedExtension_t));
    chrg_int_limits_ext -> extensionID = 7;
    ConductiveChargingInterfaceLimitations_t *chrg_int_limits = (ConductiveChargingInterfaceLimitations_t *)calloc(1, sizeof(ConductiveChargingInterfaceLimitations_t));
    chrg_int_limits -> maximumContactorTemperature = 80;
    uint8_t *chrg_int_limits_buffer = (uint8_t *)calloc(128, sizeof(uint8_t));
    asn_enc_rval_t chrg_int_limits_enc_rval = der_encode_to_buffer(&asn_DEF_ConductiveChargingInterfaceLimitations,
                    chrg_int_limits, chrg_int_limits_buffer, 128);
    //dlog(DLOG_LEVEL_INFO, "Conductive Charging Interface Limits data encoded: %zu bytes\n", chrg_int_limits_enc_rval.encoded);
    OCTET_STRING_fromBuf(&chrg_int_limits_ext -> extensionValue, (char *)chrg_int_limits_buffer,
                    chrg_int_limits_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, chrg_int_limits_ext);
    free(chrg_int_limits_buffer);

    /* ExtensionID 8 - EV Characteristics extension */
    StandardizedExtension_t *evChar_ext = (StandardizedExtension_t *)calloc(1, sizeof(StandardizedExtension_t));
    evChar_ext -> extensionID = 8;
    EVCharacteristics_t *evChar = (EVCharacteristics_t *)calloc(1, sizeof(EVCharacteristics_t));
    evChar -> vehicleIdentificationNumber = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
    evChar -> evccSoftwareVersion = (UTF8String_t *)calloc(1, sizeof(UTF8String_t));
    const uint8_t vin[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
    const unsigned char evcc_sw[] = "v2.5.6_20241031";
    OCTET_STRING_fromBuf(evChar -> vehicleIdentificationNumber, (char *)vin, sizeof(vin));
    OCTET_STRING_fromBuf(evChar -> evccSoftwareVersion, (char *)evcc_sw, sizeof(evcc_sw));
    uint8_t *evChar_buffer = (uint8_t *)calloc(128, sizeof(uint8_t));
    asn_enc_rval_t evChar_enc_rval = der_encode_to_buffer(&asn_DEF_EVCharacteristics, evChar, evChar_buffer, 128);
    //dlog(DLOG_LEVEL_INFO, "EV Characteristics data encoded: %zu bytes\n", evChar_enc_rval.encoded);
    OCTET_STRING_fromBuf(&evChar_ext -> extensionValue, (char *)evChar_buffer, evChar_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, evChar_ext);
    free(evChar_buffer);

    /* ExtensionID 9 - Charging Station Characteristics extension */
    /* Using placeholder values for evseID and EVSE Software version */
    StandardizedExtension_t *evseChar_ext = (StandardizedExtension_t *)calloc(1,sizeof(StandardizedExtension_t));
    evseChar_ext -> extensionID = 9;
    ChargingStationCharacteristics_t *evseChar = (ChargingStationCharacteristics_t *)calloc(1, sizeof(ChargingStationCharacteristics_t));
    evseChar -> evseID = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
    evseChar -> seccSoftwareVersion = (UTF8String_t *)calloc(1, sizeof(UTF8String_t));
    const uint8_t evseID[] = {0x08, 0x00, 0x27, 0x0F, 0x1D, 0x55};
    const char evse_sw[] = "vXX.XX.XX";
    OCTET_STRING_fromBuf(evseChar -> evseID, (char *)evseID, sizeof(evseID));
    OCTET_STRING_fromBuf(evseChar -> seccSoftwareVersion, evse_sw, sizeof(evse_sw));
    uint8_t *evseChar_buffer = (uint8_t *)calloc(128, sizeof(uint8_t));
    asn_enc_rval_t evseChar_enc_rval = der_encode_to_buffer(&asn_DEF_ChargingStationCharacteristics, evseChar, evseChar_buffer, 128);
    //dlog(DLOG_LEVEL_INFO, "EVSE Characteristics data encoded: %zu bytes\n", evseChar_enc_rval.encoded);
    OCTET_STRING_fromBuf(&evseChar_ext -> extensionValue, (char *)evseChar_buffer, evseChar_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, evseChar_ext);
    free(evseChar_buffer);

    /* The following commented code block can be used for debugging asn1 encode output */
    //xer_fprint(stdout, &asn_DEF_Extensions, extensions);
    /* dlog(DLOG_LEVEL_INFO, "Number of standardized extensions: %ld", extensions->standardized.list.count);
    for (int p = 0; p < extensions -> standardized.list.count; p++) {
        StandardizedExtension_t *temp = extensions -> standardized.list.array[p];
        dlog(DLOG_LEVEL_INFO, "Extension ID: %ld, Value Size: %ld", temp -> extensionID, temp -> extensionValue.size);
    } */

    asn_enc_rval_t ec = der_encode_to_buffer(&asn_DEF_Extensions, extensions, buffer_esdp + offset, MAX_ESDP_RESPONSE_PAYLOAD_LEN);
    if (ec.encoded <= 0) {
        dlog(DLOG_LEVEL_ERROR, "Failed to encode ESDP Extensions to ESDP buffer. encoded: %ld", ec.encoded);
        dlog(DLOG_LEVEL_ERROR, "DER encoding failed at type: %s", ec.failed_type -> name);
        return -1;
    } else {
        dlog(DLOG_LEVEL_INFO, "ESDP extensions data encoded: %zu bytes", ec.encoded);
        offset += ec.encoded;
    }

    return offset;
}

/* Create response packet for ESDP */
int esdp_create_response(uint8_t* buffer_esdp, struct sockaddr_in6* addr, enum sdp_security security,
                        enum sdp_transport_protocol proto) {
    int offset = SDP_HEADER_LEN; // Header length is same for both SDP and ESDP
    int encode_return;
    
    // Write ESDP Version
    buffer_esdp[offset++] = (ESDP_VERSION >> 8) & 0xff;
    buffer_esdp[offset++] = ESDP_VERSION & 0xff;
    
    // Write Max V2GTP Payload Size
    buffer_esdp[offset++] = (ESDP_MAX_V2GTP_PAYLOAD_SIZE >> 8) & 0xff;
    buffer_esdp[offset++] = ESDP_MAX_V2GTP_PAYLOAD_SIZE & 0xff;

    /* Now fill in the rest of the buffer with ESDP Extensions payload */
    encode_return = encode_ESDPRes_Extensions(buffer_esdp, offset, addr, security);
    if (encode_return > 0) {
        offset = encode_return;
    }

    /* now fill in the header with payload length */
    sdp_write_header(buffer_esdp, ESDP_RESPONSE_TYPE, offset - SDP_HEADER_LEN);

    return offset;
}

/*
 * Sends a SDP response packet
 */
int sdp_send_response(int sdp_socket, struct sdp_query* sdp_query) {
    uint8_t buffer[SDP_HEADER_LEN + SDP_RESPONSE_PAYLOAD_LEN];
    int rv = 0;

    /* at the moment we only understand TCP protocol */
    if (sdp_query->proto_requested != SDP_TRANSPORT_PROTOCOL_TCP) {
        dlog(DLOG_LEVEL_ERROR, "SDP requested unsupported protocol 0x%02x, announcing nothing",
             sdp_query->proto_requested);
        return 1;
    }

    switch (sdp_query->security_requested) {
    case SDP_SECURITY_TLS:
        if (sdp_query->v2g_ctx->local_tls_addr) {
            dlog(DLOG_LEVEL_INFO, "SDP requested TLS, announcing TLS");
            sdp_create_response(buffer, sdp_query->v2g_ctx->local_tls_addr, SDP_SECURITY_TLS,
                                SDP_TRANSPORT_PROTOCOL_TCP);
            break;
        }
        if (sdp_query->v2g_ctx->local_tcp_addr) {
            dlog(DLOG_LEVEL_INFO, "SDP requested TLS, announcing NO-TLS");
            sdp_create_response(buffer, sdp_query->v2g_ctx->local_tcp_addr, SDP_SECURITY_NONE,
                                SDP_TRANSPORT_PROTOCOL_TCP);
            break;
        }
        dlog(DLOG_LEVEL_ERROR, "SDP requested TLS, announcing nothing");
        return 1;

    case SDP_SECURITY_NONE:
        if (sdp_query->v2g_ctx->local_tcp_addr) {
            dlog(DLOG_LEVEL_INFO, "SDP requested NO-TLS, announcing NO-TLS");
            sdp_create_response(buffer, sdp_query->v2g_ctx->local_tcp_addr, SDP_SECURITY_NONE,
                                SDP_TRANSPORT_PROTOCOL_TCP);
            break;
        }
        if (sdp_query->v2g_ctx->local_tls_addr) {
            dlog(DLOG_LEVEL_INFO, "SDP requested NO-TLS, announcing TLS");
            sdp_create_response(buffer, sdp_query->v2g_ctx->local_tls_addr, SDP_SECURITY_TLS,
                                SDP_TRANSPORT_PROTOCOL_TCP);
            break;
        }
        dlog(DLOG_LEVEL_ERROR, "SDP requested NO-TLS, announcing nothing");
        return 1;

    default:
        dlog(DLOG_LEVEL_ERROR, "SDP requested unsupported security 0x%02x, announcing nothing",
             sdp_query->security_requested);
        return 1;
    }

    if (sendto(sdp_socket, buffer, sizeof(buffer), 0, (struct sockaddr*)&sdp_query->remote_addr,
               sizeof(struct sockaddr_in6)) != sizeof(buffer)) {
        rv = -1;
    }
    if (DEBUG) {
        char addrbuf[INET6_ADDRSTRLEN] = {0};
        const char* addr;
        int saved_errno = errno;

        addr = inet_ntop(AF_INET6, &sdp_query->remote_addr.sin6_addr, addrbuf, sizeof(addrbuf));
        if (rv == 0) {
            dlog(DLOG_LEVEL_INFO, "sendto([%s]:%" PRIu16 ") succeeded", addr, ntohs(sdp_query->remote_addr.sin6_port));
        } else {
            dlog(DLOG_LEVEL_ERROR, "sendto([%s]:%" PRIu16 ") failed: %s", addr, ntohs(sdp_query->remote_addr.sin6_port),
                 strerror(saved_errno));
        }
    }

    return rv;
}

/*
 * Sends a response packet for ESDP
 */
int esdp_send_response(int esdp_socket, struct sdp_query* sdp_query) {
    uint8_t buffer_esdp[SDP_HEADER_LEN + MAX_ESDP_RESPONSE_PAYLOAD_LEN];
    int rv = 0;
    int esdp_response_size;

    /* at the moment we only understand TCP protocol */
    if (sdp_query->proto_requested != SDP_TRANSPORT_PROTOCOL_TCP) {
        dlog(DLOG_LEVEL_ERROR, "ESDP requested unsupported protocol 0x%02x, announcing nothing",
             sdp_query->proto_requested);
        return 1;
    }

    switch (sdp_query->security_requested) {
    case SDP_SECURITY_TLS:
        if (sdp_query->v2g_ctx->local_tls_addr) {
            dlog(DLOG_LEVEL_INFO, "ESDP requested TLS, announcing TLS");
            esdp_response_size = esdp_create_response(buffer_esdp, sdp_query->v2g_ctx->local_tls_addr, SDP_SECURITY_TLS,
                                SDP_TRANSPORT_PROTOCOL_TCP);
            break;
        }
        if (sdp_query->v2g_ctx->local_tcp_addr) {
            dlog(DLOG_LEVEL_INFO, "ESDP requested TLS, announcing NO-TLS");
            esdp_response_size = esdp_create_response(buffer_esdp, sdp_query->v2g_ctx->local_tcp_addr, SDP_SECURITY_NONE,
                                SDP_TRANSPORT_PROTOCOL_TCP);
            break;
        }
        dlog(DLOG_LEVEL_ERROR, "ESDP requested TLS, announcing nothing");
        return 1;

    case SDP_SECURITY_NONE:
        if (sdp_query->v2g_ctx->local_tcp_addr) {
            dlog(DLOG_LEVEL_INFO, "ESDP requested NO-TLS, announcing NO-TLS");
            esdp_response_size = esdp_create_response(buffer_esdp, sdp_query->v2g_ctx->local_tcp_addr, SDP_SECURITY_NONE,
                                SDP_TRANSPORT_PROTOCOL_TCP);
            break;
        }
        if (sdp_query->v2g_ctx->local_tls_addr) {
            dlog(DLOG_LEVEL_INFO, "ESDP requested NO-TLS, announcing TLS");
            esdp_response_size = esdp_create_response(buffer_esdp, sdp_query->v2g_ctx->local_tls_addr, SDP_SECURITY_TLS,
                                SDP_TRANSPORT_PROTOCOL_TCP);
            break;
        }
        dlog(DLOG_LEVEL_ERROR, "ESDP requested NO-TLS, announcing nothing");
        return 1;

    default:
        dlog(DLOG_LEVEL_ERROR, "ESDP requested unsupported security 0x%02x, announcing nothing",
             sdp_query->security_requested);
        return 1;
    }

    int return_status = sendto(esdp_socket, buffer_esdp, esdp_response_size, 0, (struct sockaddr*)&sdp_query->remote_addr,
        sizeof(struct sockaddr_in6));

    if (return_status != esdp_response_size) {
        rv = -1;
    }
    if (DEBUG) {
        char addrbuf[INET6_ADDRSTRLEN] = {0};
        const char* addr;
        int saved_errno = errno;

        addr = inet_ntop(AF_INET6, &sdp_query->remote_addr.sin6_addr, addrbuf, sizeof(addrbuf));
        if (rv == 0) {
            dlog(DLOG_LEVEL_INFO, "sendto([%s]:%" PRIu16 ") succeeded for ESDP", addr, ntohs(sdp_query->remote_addr.sin6_port));
        } else {
            dlog(DLOG_LEVEL_ERROR, "sendto([%s]:%" PRIu16 ") failed: %s for ESDP", addr, ntohs(sdp_query->remote_addr.sin6_port),
                 strerror(saved_errno));
        }
    }
    
    dlog(DLOG_LEVEL_INFO, "Size of ESDPRes message sent: %zu bytes", return_status);

    return rv;
}

// Function to decode the Standardized ESDP extensions
int decode_standardized_extensions(const StandardizedExtensions_t *extensions, struct sdp_query* sdp_query) {
    /* Returns 1 if unable to decode Standardized ESDP extensions and 0 otherwise */
    /* Requested Security and Transport must be updated in the "sdp_query" struct with the values decoded in HLC Extension (ID 4).
        Currently these are hardcoded to No-TLS and TCP respectively in "sdp_listen" under esdp */
    if (!extensions) {
        dlog(DLOG_LEVEL_ERROR, "No Standardized ESDP extensions to decode");
        return 1;
    }

    for (int i = 0; i < extensions -> list.count; i++) {
        StandardizedExtension_t *ext = extensions -> list.array[i];
        if (ext) {
            //dlog(DLOG_LEVEL_INFO, "Extension ID: %ld", ext -> extensionID);

            uint8_t *extensionVal_buf = ext -> extensionValue.buf;
            ssize_t extensionVal_size = ext -> extensionValue.size;

            switch(ext -> extensionID) {
                case 1: {
                    ChargingInterface_t *ev_chrg_int = NULL;
                    asn_dec_rval_t rval_chrg_int = ber_decode(NULL, &asn_DEF_ChargingInterface, (void **)&ev_chrg_int, 
                        extensionVal_buf, extensionVal_size);
                    
                    if (rval_chrg_int.code == RC_OK) {
                        dlog(DLOG_LEVEL_INFO, "Successfully decoded Charging Interface extension");
                        /* Placeholder switch block for future code expansion */
                        switch(*ev_chrg_int) {
                            case ChargingInterface_nacs:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: NACS");
                                break;
                            case ChargingInterface_ccs1:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: CCS1");
                                break;
                            case ChargingInterface_ccs2:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: CCS2");
                                break;
                            case ChargingInterface_chademo:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: CHAdeMO");
                                break;
                            case ChargingInterface_chaoji:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: Chaoji");
                                break;
                            case ChargingInterface_type_1:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: Type-1");
                                break;
                            case ChargingInterface_type_2:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: Type-2");
                                break;
                            case ChargingInterface_mcs:
                                dlog(DLOG_LEVEL_INFO, "     Charging Interface: MCS");
                                break;
                            default:
                                dlog(DLOG_LEVEL_ERROR, "    Unknown Charging Interface");
                                break;
                        }
                        ASN_STRUCT_FREE(asn_DEF_ChargingInterface, ev_chrg_int);
                    } else {
                        dlog(DLOG_LEVEL_ERROR, "Failed to decode Charging Interface extension");
                    }
                    break;
                }
                case 2: {
                    BasicSignaling_t *ev_bsc_sgnlng = NULL;
                    asn_dec_rval_t rval_bsc_sgnlng = ber_decode(NULL, &asn_DEF_BasicSignaling, (void **)&ev_bsc_sgnlng,
                                    extensionVal_buf, extensionVal_size);
                    
                    if (rval_bsc_sgnlng.code == RC_OK) {
                        dlog(DLOG_LEVEL_INFO, "Successfully decoded Basic Signaling Protocol extension");
                        for (int k = 0; k < ev_bsc_sgnlng -> list.count; k++) {
                            /* Placeholder switch block for future code expansion */
                            switch(*ev_bsc_sgnlng -> list.array[k]) {
                                case BasicSignalingProtocol_iec61851_1_ED2:
                                    dlog(DLOG_LEVEL_INFO, "     Basic Signaling Protocol[%ld]: IEC 61851-01 Ed-02", k+1);
                                    break;
                                case BasicSignalingProtocol_iec61851_1_ED3:
                                    dlog(DLOG_LEVEL_INFO, "     Basic Signaling Protocol[%ld]: IEC 61851-01 Ed-03", k+1);
                                    break;
                                case BasicSignalingProtocol_iec61851_23_ED1:
                                    dlog(DLOG_LEVEL_INFO, "     Basic Signaling Protocol[%ld]: IEC 61851-23 Ed-01", k+1);
                                    break;
                                case BasicSignalingProtocol_iec61851_23_ED2:
                                    dlog(DLOG_LEVEL_INFO, "     Basic Signaling Protocol[%ld]: IEC 61851-23 Ed-02", k+1);
                                    break;
                                default:
                                    dlog(DLOG_LEVEL_ERROR, "    Unknown Basic Signaling Protocol");
                                    break;
                            }
                        }
                        ASN_STRUCT_FREE(asn_DEF_BasicSignaling, ev_bsc_sgnlng);
                    } else {
                        dlog(DLOG_LEVEL_ERROR, "Failed to decode Basic Signaling extension");
                    }
                    break;
                }
                case 3: {
                    IPv6Socket_t *ev_ip_socket = NULL;
                    asn_dec_rval_t rval_ip_socket = ber_decode(NULL, &asn_DEF_IPv6Socket, (void **)&ev_ip_socket,
                        extensionVal_buf, extensionVal_size);
                    
                    dlog(DLOG_LEVEL_WARNING, "ESDPReq payload includes IPv6 Socket extension");
                    break;
                }
                case 4: {
                    HighLevelCommunication_t *ev_hlc = NULL;
                    asn_dec_rval_t rval_hlc = ber_decode(NULL, &asn_DEF_HighLevelCommunication, (void **)&ev_hlc,
                        extensionVal_buf, extensionVal_size);
                    
                    if (rval_hlc.code == RC_OK) {
                        dlog(DLOG_LEVEL_INFO, "Successfully decoded HLC Extension");
                        /* Placeholder switch block for future code expansion */
                        for (int ii = 0; ii < ev_hlc -> list.count; ii++) {
                            HighLevelCommunicationTuple_t *tuple = ev_hlc -> list.array[ii];
                            switch (tuple -> hlcProtocol) {
                                case HLCProtocol_din_spec_70121_2014:
                                    break;
                                case HLCProtocol_iso_15118_2_2014:
                                    break;
                                case HLCProtocol_iso_15118_20_2022:
                                    break;
                                default:
                                    dlog(DLOG_LEVEL_ERROR, "    Unknown HLC Protocol (%ld)", tuple -> hlcProtocol);
                                    break;
                            }
                            for (int jj = 0; jj < tuple -> securityProfileTuple.list.count; jj++) {
                                SecurityProfileTuple_t *sp_tuple = tuple -> securityProfileTuple.list.array[jj];
                                switch(sp_tuple -> securityProfile) {
                                    case SecurityProfile_tcpOnly:
                                        //sdp_query->security_requested = SDP_SECURITY_NONE;
                                        break;
                                    case SecurityProfile_tls12_server:
                                        //sdp_query->security_requested = SDP_SECURITY_TLS;
                                        break;
                                    case SecurityProfile_tls13_mutual:
                                        break;
                                    default:
                                        dlog(DLOG_LEVEL_ERROR, "    Unknown Security Profile (%ld)", sp_tuple -> securityProfile);
                                        break;
                                }
                                for (int kk = 0; kk < sp_tuple -> authorizationMethod.list.count; kk++) {
                                    AuthorizationMethod_t *auth_method = sp_tuple -> authorizationMethod.list.array[kk];
                                    switch(*auth_method) {
                                        case AuthorizationMethod_eim:
                                            break;
                                        case AuthorizationMethod_pnc_2:
                                            break;
                                        case AuthorizationMethod_pnc_20:
                                            break;
                                        default:
                                            dlog(DLOG_LEVEL_ERROR, "    Unknown Authorization Method (%ld)", *auth_method);
                                            break;
                                    }
                                }
                                for (int kk = 0; kk < sp_tuple -> energyTransferMode.list.count; kk++) {
                                    EnergyTransferMode_t *energy_mode = sp_tuple -> energyTransferMode.list.array[kk];
                                    switch(*energy_mode) {
                                        case EnergyTransferMode_dc:
                                            break;
                                        case EnergyTransferMode_dc_bpt:
                                            break;
                                        case EnergyTransferMode_ac:
                                            break;
                                        case EnergyTransferMode_ac_bpt:
                                            break;
                                        default:
                                            dlog(DLOG_LEVEL_ERROR, "    Unknown Energy Transfer Mode (%ld)", *energy_mode);
                                            break;
                                    }
                                }
                            }
                        }
                        ASN_STRUCT_FREE(asn_DEF_HighLevelCommunication, ev_hlc);
                    } else {
                        dlog(DLOG_LEVEL_ERROR, "Failed to decode HLC extension");
                    }
                    break;
                }
                case 5: {
                    EMSPIdentifiers_t *ev_emsp = NULL;
                    asn_dec_rval_t rval_emsp = ber_decode(NULL, &asn_DEF_EMSPIdentifiers, (void **)&ev_emsp,
                        extensionVal_buf, extensionVal_size);
                    
                    /* if (rval_emsp.code == RC_OK) {
                        dlog(DLOG_LEVEL_INFO, "Successfully decoded EMSP Identifiers extension");
                        for (int k = 0; k < ev_emsp -> list.count; k++) {
                            dlog(DLOG_LEVEL_INFO, "EMSP Identifier[%d]: %s\n", k+1, ev_emsp -> list.array[k] -> buf);
                        }
                        ASN_STRUCT_FREE(asn_DEF_EMSPIdentifiers, ev_emsp);
                    } else {
                        dlog(DLOG_LEVEL_ERROR, "Failed to decode EMSP Identifiers extension");
                    } */
                    dlog(DLOG_LEVEL_WARNING, "ESDPReq payload includes EMSP Identifiers extension");
                    break;
                }
                case 6: {
                    DCChargingLimits_t *ev_limits = NULL;
                    asn_dec_rval_t rval_limits = ber_decode(NULL, &asn_DEF_DCChargingLimits, (void **)&ev_limits,
                                    extensionVal_buf, extensionVal_size);
                    
                    if (rval_limits.code == RC_OK) {
                        dlog(DLOG_LEVEL_INFO, "Successfully decoded DC Charging Limits extension");
                        dlog(DLOG_LEVEL_INFO, "     Maximum Voltage: %ld [V]\n", ev_limits -> maximumVoltage);
                        dlog(DLOG_LEVEL_INFO, "     Minimum Voltage: %ld [V]\n", ev_limits -> minimumVoltage);
                        ASN_STRUCT_FREE(asn_DEF_DCChargingLimits, ev_limits);
                    } else {
                        dlog(DLOG_LEVEL_ERROR,"Failed to decode DC Charging Limits extension");
                    }
                    break;
                }
                case 7: {
                    ConductiveChargingInterfaceLimitations_t *ev_interface_limits = NULL;
                    asn_dec_rval_t rval_int_limits = ber_decode(NULL, &asn_DEF_ConductiveChargingInterfaceLimitations,
                                    (void **)&ev_interface_limits, extensionVal_buf, extensionVal_size);
                    
                    if (rval_int_limits.code == RC_OK) {
                        dlog(DLOG_LEVEL_INFO, "Successfully decoded Conductive Charging Interface Limitations extension");
                        dlog(DLOG_LEVEL_INFO, "     Maximum Contactor Temp: %ld [C]\n", ev_interface_limits -> maximumContactorTemperature);
                        ASN_STRUCT_FREE(asn_DEF_ConductiveChargingInterfaceLimitations, ev_interface_limits);
                    } else {
                        dlog(DLOG_LEVEL_ERROR, "Failed to decode Conductive Charging Interface Limitations extension");
                    }
                    break;
                }
                case 8: {
                    EVCharacteristics_t *evChar = NULL;
                    asn_dec_rval_t rval_evChar = ber_decode(NULL, &asn_DEF_EVCharacteristics, (void **)&evChar,
                                    extensionVal_buf, extensionVal_size);

                    if(rval_evChar.code == RC_OK) {
                        dlog(DLOG_LEVEL_INFO, "Successfully decoded EV Characteristics extension");
                        if (evChar -> vehicleIdentificationNumber -> size > 0) {
                            dlog(DLOG_LEVEL_INFO, "     VIN (in Hex format): %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                                evChar->vehicleIdentificationNumber -> buf[0], evChar->vehicleIdentificationNumber -> buf[1],
                                evChar -> vehicleIdentificationNumber -> buf[2], evChar -> vehicleIdentificationNumber -> buf[3],
                                evChar -> vehicleIdentificationNumber -> buf[4], evChar -> vehicleIdentificationNumber -> buf[5],
                                evChar -> vehicleIdentificationNumber -> buf[6], evChar -> vehicleIdentificationNumber -> buf[7],
                                evChar -> vehicleIdentificationNumber -> buf[8], evChar -> vehicleIdentificationNumber -> buf[9],
                                evChar -> vehicleIdentificationNumber -> buf[10], evChar -> vehicleIdentificationNumber -> buf[11],
                                evChar -> vehicleIdentificationNumber -> buf[12], evChar -> vehicleIdentificationNumber -> buf[13],
                                evChar -> vehicleIdentificationNumber -> buf[14], evChar -> vehicleIdentificationNumber -> buf[15],
                                evChar -> vehicleIdentificationNumber -> buf[16]);
                            for (size_t i = 0; i < evChar -> vehicleIdentificationNumber -> size; i++) {
                                //printf("%02X", evChar -> vehicleIdentificationNumber -> buf[i]);
                            }
                        } else {
                            dlog(DLOG_LEVEL_WARNING, "Vehicle Identification Number was NOT communicated");
                        }
                        if (evChar -> evccSoftwareVersion -> size > 0) {
                            dlog(DLOG_LEVEL_INFO, "     EVCC Software Version: %.*s\n", (int)evChar -> evccSoftwareVersion -> size,
                                evChar -> evccSoftwareVersion -> buf);
                        } else {
                            dlog(DLOG_LEVEL_WARNING, "EVCC Software version was NOT communicated");
                        }
                        ASN_STRUCT_FREE(asn_DEF_EVCharacteristics, evChar);
                    } else {
                        dlog(DLOG_LEVEL_ERROR, "Failed to decode EV Characteristics extension");
                    }
                    break;
                }
                case 9: {
                    dlog(DLOG_LEVEL_WARNING, "ESDPReq payload includes Charging Station Characteristics extension");
                    break;
                }
                default:
                    dlog(DLOG_LEVEL_WARNING, "Unknown Extension ID: %ld", ext -> extensionID);
                    break;
            }
        }
    }

    /* Since Transport protocol is not included in HLC Extension under ESDP Standardized extensions,
        this is currently being hardcoded*/
    sdp_query->proto_requested = SDP_TRANSPORT_PROTOCOL_TCP;
    
    /* Currently hardcoding security to No-TLS. This line can be removed when this value starts getting 
        set from decoded HLC Extension */
    sdp_query->security_requested = SDP_SECURITY_NONE;

    return 0;
}

// Function to decode ESDP extensions in V2GTP payload in ESDPReq message
int decode_esdp_payload(uint8_t* buffer, struct sdp_query* sdp_query, ssize_t recv_len) {
    /* Returns 1 if unable to decode esdp extensions and 0 otherwise*/

    int dec_std_ext_return;
    ssize_t asn1_payload_size = recv_len - SDP_HEADER_LEN - 6;

    // Create a new buffer which only contains the ASN1 encoded ESDP extensions
    uint8_t *buffer_esdp = (uint8_t *)calloc(asn1_payload_size, sizeof(uint8_t)); // "6" Since ESDPVersion, max payload size, and security/transport require 2 bytes each.

    // Copy ESDP Extensions from received message buffer to the new buffer.
    memcpy(buffer_esdp, buffer + SDP_HEADER_LEN + 6, recv_len);

    /* Decode the buffer into "extensions" object*/
    Extensions_t *extensions = (Extensions_t *)calloc(1, sizeof(Extensions_t));
    asn_dec_rval_t rval = asn_decode(NULL, ATS_DER, &asn_DEF_Extensions, (void **)&extensions, buffer_esdp, asn1_payload_size);
    if (rval.code != RC_OK) {
        dlog(DLOG_LEVEL_ERROR, "Decoding failed at byte %ld", rval.consumed);
        ASN_STRUCT_FREE(asn_DEF_Extensions, extensions);
        return 1;
    } else {
        dlog(DLOG_LEVEL_INFO, "Successully decoded ESDPReq payload");
    }

    /* Decode Standardized Extensions*/
    dec_std_ext_return = decode_standardized_extensions(&extensions -> standardized, sdp_query);

    if (dec_std_ext_return) {
        dlog(DLOG_LEVEL_ERROR, "Failed to decode Standardized Extensions in ESDPReq payload");
    } else {
        dlog(DLOG_LEVEL_INFO, "Successfully decoded Standardized Extensions in ESDPReq payload");
    }
    
    /* Check presence of external extensions per ISO/PAS CD 15118-200:2024(E)*/
    if (extensions -> external) {
        dlog(DLOG_LEVEL_INFO, "External ESDP Extensions present in the received ESDPReq message");
        // Define a function to decode external extensions and call it here.
    } else {
        dlog(DLOG_LEVEL_INFO, "External ESDP Extensions NOT present in the received ESDPReq message");
    }

    return 0;
}

int sdp_init(struct v2g_context* v2g_ctx) {
    struct sockaddr_in6 sdp_addr = {AF_INET6, htons(SDP_SRV_PORT)};
    struct sockaddr_in6 esdp_addr = {AF_INET6, htons(ESDP_SRV_PORT)}; // For ESDP
    struct ipv6_mreq mreq = {{IN6ADDR_ALLNODES}, 0};
    int enable = 1;

    mreq.ipv6mr_interface = if_nametoindex(v2g_ctx->if_name);
    if (!mreq.ipv6mr_interface) {
        dlog(DLOG_LEVEL_ERROR, "No such interface: %s", v2g_ctx->if_name);
        return -1;
    }

    /* create receiving socket */
    v2g_ctx->sdp_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (v2g_ctx->sdp_socket == -1) {
        dlog(DLOG_LEVEL_ERROR, "socket() failed: %s", strerror(errno));
        return -1;
    }
    
    /* create receiving esdp socket for ESDP*/
    v2g_ctx->esdp_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (v2g_ctx->esdp_socket == -1) {
        dlog(DLOG_LEVEL_ERROR, "socket() failed for ESDP: %s", strerror(errno));
        return -1;
    }    

    if (setsockopt(v2g_ctx->sdp_socket, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) == -1) {
        dlog(DLOG_LEVEL_ERROR, "setsockopt(SO_REUSEPORT) failed: %s", strerror(errno));
        close(v2g_ctx->sdp_socket);
        return -1;
    }
    
    /* enable the Option "SO_REUSEPORT" for ESDP socket */
    if (setsockopt(v2g_ctx->esdp_socket, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) == -1) {
        dlog(DLOG_LEVEL_ERROR, "setsockopt(SO_REUSEPORT) failed for ESDP: %s", strerror(errno));
        close(v2g_ctx->esdp_socket);
        return -1;
    }
    
    sdp_addr.sin6_addr = in6addr_any;
    esdp_addr.sin6_addr = in6addr_any; // For ESDP

    if (bind(v2g_ctx->sdp_socket, (struct sockaddr*)&sdp_addr, sizeof(sdp_addr)) == -1) {
        dlog(DLOG_LEVEL_ERROR, "bind() failed: %s", strerror(errno));
        close(v2g_ctx->sdp_socket);
        return -1;
    }
    
    /* bind esdp_socket to esdp_addr for ESDP */
    if (bind(v2g_ctx->esdp_socket, (struct sockaddr*)&esdp_addr, sizeof(esdp_addr)) == -1) {
        dlog(DLOG_LEVEL_ERROR, "bind() failed for ESDP socket: %s", strerror(errno));
        close(v2g_ctx->esdp_socket);
        return -1;
    }
    
    dlog(DLOG_LEVEL_INFO, "SDP socket setup succeeded");
    dlog(DLOG_LEVEL_INFO, "ESDP socket setup succeeded"); // For ESDP

    /* bind only to specified device */
    if (setsockopt(v2g_ctx->sdp_socket, SOL_SOCKET, SO_BINDTODEVICE, v2g_ctx->if_name, strlen(v2g_ctx->if_name)) ==
        -1) {
        dlog(DLOG_LEVEL_ERROR, "setsockopt(SO_BINDTODEVICE) failed: %s", strerror(errno));
        close(v2g_ctx->sdp_socket);
        return -1;
    }

    /* bind ESDP socket only to specified device for ESDP */
    if (setsockopt(v2g_ctx->esdp_socket, SOL_SOCKET, SO_BINDTODEVICE, v2g_ctx->if_name, strlen(v2g_ctx->if_name)) ==
        -1) {
        dlog(DLOG_LEVEL_ERROR, "setsockopt(SO_BINDTODEVICE) failed for ESDP: %s", strerror(errno));
        close(v2g_ctx->esdp_socket);
        return -1;
    }

    dlog(DLOG_LEVEL_TRACE, "bind only to specified device");
    dlog(DLOG_LEVEL_TRACE, "bind only to specified device for ESDP");

    /* join multicast group */
    if (setsockopt(v2g_ctx->sdp_socket, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1) {
        dlog(DLOG_LEVEL_ERROR, "setsockopt(IPV6_JOIN_GROUP) failed: %s", strerror(errno));
        close(v2g_ctx->sdp_socket);
        return -1;
    }

    /* join multicast group for ESDP socket */
    if (setsockopt(v2g_ctx->esdp_socket, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1) {
        dlog(DLOG_LEVEL_ERROR, "setsockopt(IPV6_JOIN_GROUP) failed for ESDP: %s", strerror(errno));
        close(v2g_ctx->esdp_socket);
        return -1;
    }

    dlog(DLOG_LEVEL_TRACE, "joined multicast group");
    dlog(DLOG_LEVEL_TRACE, "joined multicast group for ESDP");

    return 0;
}

int sdp_listen(struct v2g_context* v2g_ctx) {
    /* Init pollfd struct */
    struct pollfd pollfd = {v2g_ctx->sdp_socket, POLLIN, 0};

    /* Init pollfd struct for ESDP socket */
    struct pollfd pollfd_esdp = {v2g_ctx->esdp_socket, POLLIN, 0};

    while (!v2g_ctx->shutdown) {
        uint8_t buffer[SDP_HEADER_LEN + SDP_REQUEST_PAYLOAD_LEN];
        uint8_t buffer_esdp[SDP_HEADER_LEN + MAX_ESDP_REQUEST_PAYLOAD_LEN]; // For ESDP
        memset(buffer_esdp, 0, sizeof(buffer_esdp)); // For ESDP
        char addrbuf[INET6_ADDRSTRLEN] = {0};
        const char* addr = addrbuf;
        struct sdp_query sdp_query = {
            .v2g_ctx = v2g_ctx,
        };
        socklen_t addrlen = sizeof(sdp_query.remote_addr);
        int func_return;
        int decode_return;

        /* Check if data was received on socket */
        signed status = poll(&pollfd, 1, POLL_TIMEOUT);

        if (status == -1) {
            if (errno == EINTR) { // If the call did not succeed because it was interrupted
                continue;
            } else {
                dlog(DLOG_LEVEL_ERROR, "poll() failed: %s", strerror(errno));
                continue;
            }
        }
        /* If new data was received, handle sdp request */
        if (status > 0) {
            ssize_t len = recvfrom(v2g_ctx->sdp_socket, buffer, sizeof(buffer), 0,
                                   (struct sockaddr*)&sdp_query.remote_addr, &addrlen);
            if (len == -1) {
                if (errno != EINTR)
                    dlog(DLOG_LEVEL_ERROR, "recvfrom() failed: %s", strerror(errno));
                continue;
            }

            addr = inet_ntop(AF_INET6, &sdp_query.remote_addr.sin6_addr, addrbuf, sizeof(addrbuf));

            if (len != sizeof(buffer)) {
                dlog(DLOG_LEVEL_WARNING, "Discarded packet from [%s]:%" PRIu16 " due to unexpected length %zd", addr,
                     ntohs(sdp_query.remote_addr.sin6_port), len);
                continue;
            }

            if (sdp_validate_header(buffer, SDP_REQUEST_TYPE, SDP_REQUEST_PAYLOAD_LEN)) {
                dlog(DLOG_LEVEL_WARNING, "Packet with invalid SDP header received from [%s]:%" PRIu16, addr,
                     ntohs(sdp_query.remote_addr.sin6_port));
                continue;
            }

            sdp_query.security_requested = (sdp_security)buffer[SDP_HEADER_LEN + 0];
            sdp_query.proto_requested = (sdp_transport_protocol)buffer[SDP_HEADER_LEN + 1];

            dlog(DLOG_LEVEL_INFO, "Received packet from [%s]:%" PRIu16 " with security 0x%02x and protocol 0x%02x",
                 addr, ntohs(sdp_query.remote_addr.sin6_port), sdp_query.security_requested, sdp_query.proto_requested);

            sdp_send_response(v2g_ctx->sdp_socket, &sdp_query);
        }
        
        /* Check if data was received on esdp socket for ESDP */
        signed status_esdp = poll(&pollfd_esdp, 1, POLL_TIMEOUT);
        
        // If the call did not succeed because it was interrupted for ESDP
        if (status_esdp == -1) {
            if (errno == EINTR) {
                continue;
            } else {
                dlog(DLOG_LEVEL_ERROR, "poll() failed for ESDP: %s", strerror(errno));
                continue;
            }
        }
        /* If new data was received, handle esdp request for ESDP */
        if (status_esdp > 0) {
            ssize_t len = recvfrom(v2g_ctx->esdp_socket, buffer_esdp, sizeof(buffer_esdp), 0,
                                   (struct sockaddr*)&sdp_query.remote_addr, &addrlen);
            
            uint32_t reported_len;  // Payload size/length reported in V2GTP Header  
            reported_len = (buffer_esdp[4] << 24) + (buffer_esdp[5] << 16) + (buffer_esdp[6] << 8) + buffer_esdp[7];
            uint16_t max_v2gtp_payload_size;    // Maximum payload size in bytes that EVCC can receive. Per [V2G200-52-3] in ISO/PAS CD 15118-200:2024(E) - STANDARD NOT YET PUBLISHED

            if (len == -1) {
                if (errno != EINTR)
                    dlog(DLOG_LEVEL_ERROR, "recvfrom() failed for ESDP: %s", strerror(errno));
                continue;
            } else {
                dlog(DLOG_LEVEL_INFO, "Recieved ESDP packet. Reported payload length is %" PRIu32 " bytes while received payload length is %zu bytes",
                     reported_len ,len - SDP_HEADER_LEN);
            }

            addr = inet_ntop(AF_INET6, &sdp_query.remote_addr.sin6_addr, addrbuf, sizeof(addrbuf));

            func_return = esdp_validate_header(buffer_esdp, ESDP_REQUEST_TYPE, MAX_ESDP_REQUEST_PAYLOAD_LEN, ESDP_VERSION);
            
            if (func_return == -1) {
                dlog(DLOG_LEVEL_WARNING, "Packet with invalid ESDP header received from [%s]:%" PRIu16, addr,
                     ntohs(sdp_query.remote_addr.sin6_port));
                continue;
            } else if (func_return == 1) {
            	continue;
            }
            
            max_v2gtp_payload_size = (buffer_esdp[SDP_HEADER_LEN + 2] << 8) + buffer_esdp[SDP_HEADER_LEN + 3];
            if (max_v2gtp_payload_size > 0) {
                dlog(DLOG_LEVEL_INFO, "EVCC's reported Max V2GTP Payload size: %" PRIu16 " bytes", max_v2gtp_payload_size);
            } else {
                dlog(DLOG_LEVEL_ERROR, "Invalid Max V2GTP Payload size");
            }
            
            // Decode ESDP payload here 
            decode_return = decode_esdp_payload(buffer_esdp, &sdp_query, len);

            if (decode_return) {
                dlog(DLOG_LEVEL_WARNING, "Unable to decode ESDP Extensions from ESDPReq message. Discarded ESDP packet received from [%s]:%" PRIu16,
                 ntohs(sdp_query.remote_addr.sin6_port));
                continue;
            }

            dlog(DLOG_LEVEL_INFO, "Received ESDP packet from [%s]:%" PRIu16 " with security 0x%02x and protocol 0x%02x",
                 addr, ntohs(sdp_query.remote_addr.sin6_port), sdp_query.security_requested, sdp_query.proto_requested);

            esdp_send_response(v2g_ctx->esdp_socket, &sdp_query);
        }
    }

    if (close(v2g_ctx->sdp_socket) == -1) {
        dlog(DLOG_LEVEL_ERROR, "close() failed: %s", strerror(errno));
    }

    if (close(v2g_ctx->esdp_socket) == -1) {
        dlog(DLOG_LEVEL_ERROR, "close() failed for ESDP socket: %s", strerror(errno));
    }

    return 0;
}
