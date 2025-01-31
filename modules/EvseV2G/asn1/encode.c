#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "all_asn1c_headers.h" // This contains all header files in the repo

/* Write the encoded output into a FILE stream */
static int write_out(const void *buffer, size_t size, void *app_key) {
    FILE *out_fp = app_key;
    return (fwrite(buffer, 1, size, out_fp) == size) ? 0 : -1;
}

/* Cleanup function to free resources in case of error */
void cleanup_extensions(Extensions_t *extensions) {
	if (!extensions) return;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <output.ber>\n", argv[0]);
        exit(1);
    }

    const char *filename = argv[1];
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Error opening file for writing");
        exit(1);
    }
    
    /* Create and populate Extensions */
    Extensions_t *extensions = calloc(1, sizeof(Extensions_t));
    if (!extensions) {
    	perror("Failed to allocate memory for Extensions");
    	return 1;
    }
    
    /* ExtensionID 1 - Charging interface extension */
    StandardizedExtension_t *charging_interface_ext = calloc(1, sizeof(StandardizedExtension_t));
    if (!charging_interface_ext) {
    	perror("Failed to allocate memory for Charging Interface Extension");
        ASN_STRUCT_FREE(asn_DEF_StandardizedExtension, charging_interface_ext);
    	fclose(fp);
    	return 1;
    }
    charging_interface_ext -> extensionID = 1;
    ChargingInterface_t charging_interface = ChargingInterface_ccs1;
    uint8_t *ci_buffer = calloc(128, sizeof(uint8_t));
    asn_enc_rval_t ci_enc_rval = der_encode_to_buffer(&asn_DEF_ChargingInterface, &charging_interface,
                    ci_buffer, 128);
    printf("ChargingInterface data encoded: %zu bytes\n", ci_enc_rval.encoded);
    OCTET_STRING_fromBuf(&charging_interface_ext -> extensionValue, (char *)ci_buffer, ci_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, charging_interface_ext);
    free(ci_buffer);


    /* ExtensionID 2 - Basic signaling extension */
    StandardizedExtension_t *basic_signaling_ext = calloc(1, sizeof(StandardizedExtension_t));
    if (!basic_signaling_ext) {
    	perror("Failed to allocate memory for Basic Signaling Extension");
    	ASN_STRUCT_FREE(asn_DEF_StandardizedExtension, basic_signaling_ext);  
    	fclose(fp);
    	return 1;
    }    
    basic_signaling_ext -> extensionID = 2;
    BasicSignaling_t *basic_signaling = calloc(1, sizeof(BasicSignaling_t));
    ASN_SEQUENCE_ADD(&basic_signaling -> list, &(BasicSignalingProtocol_t){BasicSignalingProtocol_iec61851_1_ED2});
    ASN_SEQUENCE_ADD(&basic_signaling -> list, &(BasicSignalingProtocol_t){BasicSignalingProtocol_iec61851_1_ED3});
    ASN_SEQUENCE_ADD(&basic_signaling -> list, &(BasicSignalingProtocol_t){BasicSignalingProtocol_iec61851_23_ED1});
    ASN_SEQUENCE_ADD(&basic_signaling -> list, &(BasicSignalingProtocol_t){BasicSignalingProtocol_iec61851_23_ED2});   
    uint8_t *bs_buffer = calloc(128, sizeof(uint8_t));
    asn_enc_rval_t bs_enc_rval = der_encode_to_buffer(&asn_DEF_BasicSignaling, basic_signaling, bs_buffer, 128);
    printf("Basic Signaling data encoded: %zu bytes\n", bs_enc_rval.encoded);
    OCTET_STRING_fromBuf(&basic_signaling_ext -> extensionValue, (char *)bs_buffer, bs_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, basic_signaling_ext);
    free(bs_buffer);
    
    /* ExtensionID 3 - IPv6 Socket extension */
    StandardizedExtension_t *ipv6_socket_ext = calloc(1, sizeof(StandardizedExtension_t));
    if (!ipv6_socket_ext) {
    	perror("Failed to allocate memory for IPv6 Socket Extension");
    	ASN_STRUCT_FREE(asn_DEF_StandardizedExtension, ipv6_socket_ext);  
    	fclose(fp);
    	return 1;
    }    
    ipv6_socket_ext -> extensionID = 3;
    IPv6Socket_t *ipv6_socket = calloc(1, sizeof(IPv6Socket_t));
    const char ipv6_secc_address[] = {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x79, 0xbd, 0x0f, 0xb1, 0x1d, 0xb0, 0x88, 0xa7};
    const char ipv6_secc_port[] = {0x00, 0x00, 0xef, 0x9d};
    OCTET_STRING_fromBuf(&ipv6_socket -> ipv6Address, (const char *)&ipv6_secc_address, sizeof(ipv6_secc_address));
    OCTET_STRING_fromBuf(&ipv6_socket -> tcpPort, (const char *)&ipv6_secc_port, sizeof(ipv6_secc_port));
    uint8_t *ip_buffer = calloc(128, sizeof(uint8_t));
    asn_enc_rval_t ip_enc_rval = der_encode_to_buffer(&asn_DEF_IPv6Socket, ipv6_socket, ip_buffer, 128);
    printf("IPv6 Socket data encoded: %zu bytes\n", ip_enc_rval.encoded);
    OCTET_STRING_fromBuf(&ipv6_socket_ext -> extensionValue, (char *)ip_buffer, ip_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, ipv6_socket_ext);
    free(ip_buffer);

    /* Verify ipv6 address*/
/*    for (size_t i = 0; i < ipv6_socket -> ipv6Address.size; i++) {
        printf("%02x", ipv6_socket -> ipv6Address.buf[i]);
        if (i % 2 && i != ipv6_socket -> ipv6Address.size - 1) {
            printf(":");
        }
    }
    printf("\n");   */
    
    /* Verify ipv6 tcp port*/
/*    for (size_t i = 0; i < ipv6_socket -> tcpPort.size; i++) {
        printf("%02x", ipv6_socket -> tcpPort.buf[i]);
        if (i % 2 && i != ipv6_socket -> tcpPort.size - 1) {
            printf(":");
        }
    }
    printf("\n");   */

   /* ExtensionID 4 - High Level Communication extension */
    StandardizedExtension_t *hlc_ext = calloc(1, sizeof(StandardizedExtension_t));
    if (!hlc_ext) {
    	perror("Failed to allocate memory for High Level Communication Extension");
    	ASN_STRUCT_FREE(asn_DEF_StandardizedExtension, hlc_ext);  
    	fclose(fp);
    	return 1;
    }    
    hlc_ext -> extensionID = 4;
    HighLevelCommunication_t *hlc = calloc(1, sizeof(HighLevelCommunication_t));
    if (!hlc) {
    	free(hlc_ext);
    	perror("Failed to allocate memory for High Level Communication_t object");
    	ASN_STRUCT_FREE(asn_DEF_HighLevelCommunication, hlc);  
    	fclose(fp);
    	return 1;
    }	
    
    /* First HLC Tuple - For DIN 70121:2014 (TCP with EIM with DC) */
    HighLevelCommunicationTuple_t *hlc_tuple01 = calloc(1, sizeof(HighLevelCommunicationTuple_t));
    hlc_tuple01 -> hlcProtocol = HLCProtocol_din_spec_70121_2014;
    SecurityProfileTuple_t *sec_profile01 = calloc(1, sizeof(SecurityProfileTuple_t));
    sec_profile01 -> securityProfile = SecurityProfile_tcpOnly;
    AuthorizationMethod_t *auth01 = calloc(1, sizeof(AuthorizationMethod_t));
    *auth01 = AuthorizationMethod_eim;
    EnergyTransferMode_t *mode01 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode01 = EnergyTransferMode_dc;
    ASN_SEQUENCE_ADD(&sec_profile01 -> authorizationMethod.list, auth01);
    ASN_SEQUENCE_ADD(&sec_profile01 -> energyTransferMode.list, mode01);
    ASN_SEQUENCE_ADD(&hlc_tuple01 -> securityProfileTuple.list, sec_profile01);
    ASN_SEQUENCE_ADD(&hlc -> list, hlc_tuple01);
    
    /* Second HLC Tuple - For ISO 15118-2:2014 (TCP with EIM with dc & ac) */
    HighLevelCommunicationTuple_t *hlc_tuple02 = calloc(1, sizeof(HighLevelCommunicationTuple_t));
    hlc_tuple02 -> hlcProtocol = HLCProtocol_iso_15118_2_2014;
    SecurityProfileTuple_t *sec_profile02_01 = calloc(1, sizeof(SecurityProfileTuple_t));
    sec_profile02_01 -> securityProfile = SecurityProfile_tcpOnly;
    AuthorizationMethod_t *auth02_01 = calloc(1, sizeof(AuthorizationMethod_t));
    *auth02_01 = AuthorizationMethod_eim;
    EnergyTransferMode_t *mode02_01_01 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode02_01_01 = EnergyTransferMode_dc;
    EnergyTransferMode_t *mode02_01_02 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode02_01_02 = EnergyTransferMode_ac;
    ASN_SEQUENCE_ADD(&sec_profile02_01 -> authorizationMethod.list, auth02_01);
    ASN_SEQUENCE_ADD(&sec_profile02_01 -> energyTransferMode.list, mode02_01_01);
    ASN_SEQUENCE_ADD(&sec_profile02_01 -> energyTransferMode.list, mode02_01_02);
    
    /* and (TLS12_server with EIM & PNC_2 with dc & ac) */
    SecurityProfileTuple_t *sec_profile02_02 = calloc(1, sizeof(SecurityProfileTuple_t));
    sec_profile02_02 -> securityProfile = SecurityProfile_tls12_server;
    AuthorizationMethod_t *auth02_02_01 = calloc(1, sizeof(AuthorizationMethod_t));
    *auth02_02_01 = AuthorizationMethod_eim;
    AuthorizationMethod_t *auth02_02_02 = calloc(1, sizeof(AuthorizationMethod_t));
    *auth02_02_02 = AuthorizationMethod_pnc_2;
    EnergyTransferMode_t *mode02_02_01 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode02_02_01 = EnergyTransferMode_dc;
    EnergyTransferMode_t *mode02_02_02 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode02_02_02 = EnergyTransferMode_ac;
    ASN_SEQUENCE_ADD(&sec_profile02_02 -> authorizationMethod.list, auth02_02_01);
    ASN_SEQUENCE_ADD(&sec_profile02_02 -> authorizationMethod.list, auth02_02_02);
    ASN_SEQUENCE_ADD(&sec_profile02_02 -> energyTransferMode.list, mode02_02_01);
    ASN_SEQUENCE_ADD(&sec_profile02_02 -> energyTransferMode.list, mode02_02_02);  
    ASN_SEQUENCE_ADD(&hlc_tuple02 -> securityProfileTuple.list, sec_profile02_01);
    ASN_SEQUENCE_ADD(&hlc_tuple02 -> securityProfileTuple.list, sec_profile02_02);
    ASN_SEQUENCE_ADD(&hlc -> list, hlc_tuple02);       
    
    /* Third HLC Tuple - For ISO 15118-20:2022 (TCP with EIM with dc & dc-bpt & ac & ac-bpt) */
    HighLevelCommunicationTuple_t *hlc_tuple03 = calloc(1, sizeof(HighLevelCommunicationTuple_t));
    hlc_tuple03 -> hlcProtocol = HLCProtocol_iso_15118_20_2022;
    SecurityProfileTuple_t *sec_profile03_01 = calloc(1, sizeof(SecurityProfileTuple_t));
    sec_profile03_01 -> securityProfile = SecurityProfile_tcpOnly;
    AuthorizationMethod_t *auth03_01 = calloc(1, sizeof(AuthorizationMethod_t));
    *auth03_01 = AuthorizationMethod_eim;
    EnergyTransferMode_t *mode03_01_01 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_01_01 = EnergyTransferMode_dc;
    EnergyTransferMode_t *mode03_01_02 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_01_02 = EnergyTransferMode_dc_bpt;    
    EnergyTransferMode_t *mode03_01_03 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_01_03 = EnergyTransferMode_ac;
    EnergyTransferMode_t *mode03_01_04 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_01_04 = EnergyTransferMode_ac_bpt;    
    ASN_SEQUENCE_ADD(&sec_profile03_01 -> authorizationMethod.list, auth03_01);
    ASN_SEQUENCE_ADD(&sec_profile03_01 -> energyTransferMode.list, mode03_01_01);
    ASN_SEQUENCE_ADD(&sec_profile03_01 -> energyTransferMode.list, mode03_01_02);
    ASN_SEQUENCE_ADD(&sec_profile03_01 -> energyTransferMode.list, mode03_01_03);
    ASN_SEQUENCE_ADD(&sec_profile03_01 -> energyTransferMode.list, mode03_01_04); 
    
    /* and (TLS12_server with EIM & PNC_2 with dc & dc-bpt & ac & ac-bpt) */
    SecurityProfileTuple_t *sec_profile03_02 = calloc(1, sizeof(SecurityProfileTuple_t));
    sec_profile03_02 -> securityProfile = SecurityProfile_tls12_server;
    AuthorizationMethod_t *auth03_02_01 = calloc(1, sizeof(AuthorizationMethod_t));
    *auth03_02_01 = AuthorizationMethod_eim;
    AuthorizationMethod_t *auth03_02_02 = calloc(1, sizeof(AuthorizationMethod_t));
    *auth03_02_02 = AuthorizationMethod_pnc_2;
    EnergyTransferMode_t *mode03_02_01 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_02_01 = EnergyTransferMode_dc;
    EnergyTransferMode_t *mode03_02_02 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_02_02 = EnergyTransferMode_dc_bpt;    
    EnergyTransferMode_t *mode03_02_03 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_02_03 = EnergyTransferMode_ac;
    EnergyTransferMode_t *mode03_02_04 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_02_04 = EnergyTransferMode_ac_bpt;
    ASN_SEQUENCE_ADD(&sec_profile03_02 -> authorizationMethod.list, auth03_02_01);
    ASN_SEQUENCE_ADD(&sec_profile03_02 -> authorizationMethod.list, auth03_02_02);
    ASN_SEQUENCE_ADD(&sec_profile03_02 -> energyTransferMode.list, mode03_02_01);
    ASN_SEQUENCE_ADD(&sec_profile03_02 -> energyTransferMode.list, mode03_02_02);
    ASN_SEQUENCE_ADD(&sec_profile03_02 -> energyTransferMode.list, mode03_02_03);
    ASN_SEQUENCE_ADD(&sec_profile03_02 -> energyTransferMode.list, mode03_02_04);   
    
    /* and (TLS13_mutual with EIM & PNC_2 & PNC_20 with dc & dc-bpt & ac & ac-bpt) */
    SecurityProfileTuple_t *sec_profile03_03 = calloc(1, sizeof(SecurityProfileTuple_t));
    sec_profile03_03 -> securityProfile = SecurityProfile_tls13_mutual;
    AuthorizationMethod_t *auth03_03_01 = calloc(1, sizeof(AuthorizationMethod_t));
    *auth03_03_01 = AuthorizationMethod_eim;
    AuthorizationMethod_t *auth03_03_02 = calloc(1, sizeof(AuthorizationMethod_t));
    *auth03_03_02 = AuthorizationMethod_pnc_2;
    AuthorizationMethod_t *auth03_03_03 = calloc(1, sizeof(AuthorizationMethod_t));
    *auth03_03_03 = AuthorizationMethod_pnc_20;    
    EnergyTransferMode_t *mode03_03_01 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_03_01 = EnergyTransferMode_dc;
    EnergyTransferMode_t *mode03_03_02 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_03_02 = EnergyTransferMode_dc_bpt;    
    EnergyTransferMode_t *mode03_03_03 = calloc(1, sizeof(EnergyTransferMode_t));
    *mode03_03_03 = EnergyTransferMode_ac;
    EnergyTransferMode_t *mode03_03_04 = calloc(1, sizeof(EnergyTransferMode_t));
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
    uint8_t *hlc_buffer = calloc(256, sizeof(uint8_t));
    asn_enc_rval_t hlc_enc_rval = der_encode_to_buffer(&asn_DEF_HighLevelCommunication, hlc, hlc_buffer, 256);
    printf("HLC data encoded: %zu bytes\n", hlc_enc_rval.encoded);
    OCTET_STRING_fromBuf(&hlc_ext -> extensionValue, (char *)hlc_buffer, hlc_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, hlc_ext);
    free(hlc_buffer);


    /* ExtensionID 5 - EMSP identifiers extension */
    /* Using placeholder EMSP values for now */
    StandardizedExtension_t *emsp_ids_ext = calloc(1, sizeof(StandardizedExtension_t));
//    fprintf(stdout, "Size of emsp_ids_ext object: %zu bytes\n", sizeof(*emsp_ids_ext));
    emsp_ids_ext -> extensionID = 5;
    EMSPIdentifiers_t *emsp_ids = calloc(1, sizeof(EMSPIdentifiers_t));
    EMSPIdentifier_t *emsp_id01 = calloc(1, sizeof(EMSPIdentifier_t));
    OCTET_STRING_fromBuf(emsp_id01, "abcde_0101", strlen("abcde_0101"));
    ASN_SEQUENCE_ADD(&emsp_ids -> list, emsp_id01);
    EMSPIdentifier_t *emsp_id02 = calloc(1, sizeof(EMSPIdentifier_t));
    OCTET_STRING_fromBuf(emsp_id02, "ABCDE_0102", strlen("ABCDE_0102"));
    ASN_SEQUENCE_ADD(&emsp_ids -> list, emsp_id02);
    uint8_t *emsp_buffer = calloc(128, sizeof(uint8_t));
    asn_enc_rval_t emsp_enc_rval = der_encode_to_buffer(&asn_DEF_EMSPIdentifiers, emsp_ids, emsp_buffer, 128);
    printf("EMSP Identifiers data encoded: %zu bytes\n", emsp_enc_rval.encoded);
    OCTET_STRING_fromBuf(&emsp_ids_ext -> extensionValue, (char *)emsp_buffer, emsp_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, emsp_ids_ext);
    free(emsp_buffer);
    
    
    /* ExtensionID 6 - DC charging limits extension */
    StandardizedExtension_t *dc_limits_ext = calloc(1, sizeof(StandardizedExtension_t));
    if (!dc_limits_ext) {
    	perror("Failed to allocate memory for DC Charging Limits Extension");
    	ASN_STRUCT_FREE(asn_DEF_StandardizedExtension, dc_limits_ext);
    	fclose(fp);
    	return 1;
    }
    dc_limits_ext -> extensionID = 6;
    DCChargingLimits_t *dc_limits = calloc(1, sizeof(DCChargingLimits_t));
    dc_limits -> maximumVoltage = 1000;
    dc_limits -> minimumVoltage = 250;
    uint8_t *dc_limits_buffer = calloc(128, sizeof(uint8_t));
    asn_enc_rval_t dc_limits_enc_rval = der_encode_to_buffer(&asn_DEF_DCChargingLimits, dc_limits, dc_limits_buffer, 128);
    printf("DC Charging Limits data encoded: %zu bytes\n", dc_limits_enc_rval.encoded);
    OCTET_STRING_fromBuf(&dc_limits_ext -> extensionValue, (char *)dc_limits_buffer, dc_limits_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, dc_limits_ext);
    free(dc_limits_buffer);

    /*********************************************END OF STANDARD EXTENSIONS*********************************************/

    /* (NOT STANDARD) - ExtensionID 7 - Conductive Charging Interface Limitations extension */
    StandardizedExtension_t *chrg_int_limits_ext = calloc(1, sizeof(StandardizedExtension_t));
    if (!chrg_int_limits_ext) {
    	perror("Failed to allocate memory for Conductive Charging Interface Limits Extension");
    	ASN_STRUCT_FREE(asn_DEF_StandardizedExtension, chrg_int_limits_ext);
        //ASN_STRUCT_FREE(asn_DEF_ConductiveChargingInterfaceLimitations, chrg_int_limits);
    	fclose(fp);
    	return 1;
    }
    chrg_int_limits_ext -> extensionID = 7;
    ConductiveChargingInterfaceLimitations_t *chrg_int_limits = calloc(1, sizeof(ConductiveChargingInterfaceLimitations_t));
    chrg_int_limits -> maximumContactorTemperature = 80;
    uint8_t *chrg_int_limits_buffer = calloc(128, sizeof(uint8_t));
    asn_enc_rval_t chrg_int_limits_enc_rval = der_encode_to_buffer(&asn_DEF_ConductiveChargingInterfaceLimitations,
                    chrg_int_limits, chrg_int_limits_buffer, 128);
    printf("Conductive Charging Interface Limits data encoded: %zu bytes\n", chrg_int_limits_enc_rval.encoded);
    OCTET_STRING_fromBuf(&chrg_int_limits_ext -> extensionValue, (char *)chrg_int_limits_buffer,
                    chrg_int_limits_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, chrg_int_limits_ext);
    free(chrg_int_limits_buffer);

    /* (NOT STANDARD) - ExtensionID 8 - EV Characteristics extension */
    StandardizedExtension_t *evChar_ext = calloc(1, sizeof(StandardizedExtension_t));
    if (!evChar_ext) {
    	perror("Failed to allocate memory for EV Characteristics Extension");
    	ASN_STRUCT_FREE(asn_DEF_StandardizedExtension, evChar_ext);
    	fclose(fp);
    	return 1;
    }
    evChar_ext -> extensionID = 8;
    EVCharacteristics_t *evChar = calloc(1, sizeof(EVCharacteristics_t));
    evChar -> vehicleIdentificationNumber = calloc(1, sizeof(OCTET_STRING_t));
    evChar -> evccSoftwareVersion = calloc(1, sizeof(UTF8String_t));
    const char vin[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
    const char evcc_sw[] = "v2.5.6_20241031";
    OCTET_STRING_fromBuf(evChar -> vehicleIdentificationNumber, vin, sizeof(vin));
    OCTET_STRING_fromBuf(evChar -> evccSoftwareVersion, evcc_sw, sizeof(evcc_sw));
    uint8_t *evChar_buffer = calloc(128, sizeof(uint8_t));
    asn_enc_rval_t evChar_enc_rval = der_encode_to_buffer(&asn_DEF_EVCharacteristics, evChar, evChar_buffer, 128);
    /* printf("Size of EV Characteristics: %zu bytes\n", sizeof(EVCharacteristics_t));
    printf("Size of evChar: %zu bytes\n", sizeof(*evChar));
    printf("Size of evChar->VIN: %zu bytes\n",sizeof(*evChar -> vehicleIdentificationNumber));
    printf("Size of evChar->evcc_sw: %zu bytes\n",sizeof(*evChar -> evccSoftwareVersion));
    printf("Size of vin: %zu bytes\n", sizeof(vin));
    printf("Size of evcc_sw: %zu bytes\n", sizeof(evcc_sw)); */
    printf("EV Characteristics data encoded: %zu bytes\n", evChar_enc_rval.encoded);
    OCTET_STRING_fromBuf(&evChar_ext -> extensionValue, (char *)evChar_buffer, evChar_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, evChar_ext);
    free(evChar_buffer);

    /* (NOT STANDARD) - ExtensionID 9 - Charging Station Characteristics extension */
    StandardizedExtension_t *evseChar_ext = calloc(1,sizeof(StandardizedExtension_t));
    if (!evseChar_ext) {
        perror("Failed to allocate memory for EVSE Characteristics Extension");
        ASN_STRUCT_FREE(asn_DEF_StandardizedExtension, evseChar_ext);
        fclose(fp);
        return 1;
    }
    evseChar_ext -> extensionID = 9;
    ChargingStationCharacteristics_t *evseChar = calloc(1, sizeof(ChargingStationCharacteristics_t));
    evseChar -> evseID = calloc(1, sizeof(OCTET_STRING_t));
    evseChar -> seccSoftwareVersion = calloc(1, sizeof(UTF8String_t));
    const char evseID[] = {0x5A, 0x01};
    const char evse_sw[] = "vXX.XX.XX";
    OCTET_STRING_fromBuf(evseChar -> evseID, evseID, sizeof(evseID));
    OCTET_STRING_fromBuf(evseChar -> seccSoftwareVersion, evse_sw, sizeof(evse_sw));
    uint8_t *evseChar_buffer = calloc(128, sizeof(uint8_t));
    asn_enc_rval_t evseChar_enc_rval = der_encode_to_buffer(&asn_DEF_ChargingStationCharacteristics, evseChar, evseChar_buffer, 128);
    printf("EVSE Characteristics data encoded: %zu bytes\n", evseChar_enc_rval.encoded);
    OCTET_STRING_fromBuf(&evseChar_ext -> extensionValue, (char *)evseChar_buffer, evseChar_enc_rval.encoded);
    ASN_SEQUENCE_ADD(&extensions -> standardized, evseChar_ext);
    free(evseChar_buffer);

    /* Encode the structure into DER format */
    asn_enc_rval_t ec = der_encode(&asn_DEF_Extensions, extensions, write_out, fp);
    fclose(fp);
    if (ec.encoded == -1) {
        fprintf(stderr, "Encoding failed: %s\n", ec.failed_type->name);
        cleanup_extensions(extensions);
        exit(1);
    }

    /* Print Extensions in XER format (for debugging) */
    //xer_fprint(stdout, &asn_DEF_Extensions, extensions);
    
    /* Free resources on success */
    ASN_STRUCT_FREE(asn_DEF_Extensions, extensions);  
    fprintf(stdout, "Encoded Extensions successfully to %s\n", filename);
    return 0;
}

