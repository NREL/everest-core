#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "all_asn1c_headers.h" // This contains all header files in the repo

// Function to print an OCTET STRING as a hex string
void print_octet_string(const OCTET_STRING_t *os) {
    if (!os) {
        printf("No octet string object parsed to print\n");
        return;
    }

    for (size_t j = 0; j< os -> size; j++) {
        printf("%02X ", os -> buf[j]);
    }
    printf("\n");
}

// Function to print ChargingInterface enum
void print_charging_interface(ChargingInterface_t ci) {
    if (!ci) {
        printf("No charging interface object parsed to print\n");
        return;
    }

    switch(ci) {
        case ChargingInterface_nacs:
            printf("    Decoded Charging Interface: NACS\n");
            break;
        case ChargingInterface_ccs1:
            printf("    Decoded Charging Interface: CCS1\n");
            break;
        case ChargingInterface_ccs2:
            printf("    Decoded Charging Interface: CCS2\n");
            break;
        case ChargingInterface_chademo:
            printf("    Decoded Charging Interface: CHAdeMO\n");
            break;
        case ChargingInterface_chaoji:
            printf("    Decoded Charging Interface: Chaoji\n");
            break;
        case ChargingInterface_type_1:
            printf("    Decoded Charging Interface: Type-1\n");
            break;
        case ChargingInterface_type_2:
            printf("    Decoded Charging Interface: Type-2\n");
            break;
        case ChargingInterface_mcs:
            printf("    Decoded Charging Interface: MCS\n");
            break;
        default:
            printf("    Unknown Charging Interface\n");
            break;
    }
}

// Function to print BasicSignalingProtocol enum
void print_basic_signaling_protocol(int m, BasicSignalingProtocol_t bsp) {
    if (!bsp) {
        printf("    No Basic Signaling protocol object parsed to print\n");
        return;
    }

    switch(bsp) {
        case BasicSignalingProtocol_iec61851_1_ED2:
            printf("    Decoded Basic Signaling Protocol[%d]: IEC 61851-01 Ed - 02\n", m);
            break;
        case BasicSignalingProtocol_iec61851_1_ED3:
            printf("    Decoded Basic Signaling Protocol[%d]: IEC 61851-01 Ed - 03\n", m);
            break;
        case BasicSignalingProtocol_iec61851_23_ED1:
            printf("    Decoded Basic Signaling Protocol[%d]: IEC 61851-23 Ed - 01\n", m);
            break;
        case BasicSignalingProtocol_iec61851_23_ED2:
            printf("    Decoded Basic Signaling Protocol[%d]: IEC 61851-23 Ed - 02\n", m);
            break;
        default:
            printf("    Unknown Charging Interface\n");
            break;
    }
}

// Function to decode and print the standardized extensions
void print_standardized_extensions (const StandardizedExtensions_t *extensions) {
    if (!extensions) {
        printf("No standardized extensions to print\n");
        return;
    }

    for (int i = 0; i < extensions -> list.count; i++) {
        StandardizedExtension_t *ext = extensions -> list.array[i];
        if (ext) {
            printf("Extension ID: %ld\n", ext -> extensionID);

            //printf("Extension Value (Raw): ");
            //print_octet_string(&ext -> extensionValue);

            uint8_t *extensionVal_buf = ext -> extensionValue.buf;
            size_t extensionVal_size = ext -> extensionValue.size;

            switch (ext -> extensionID) {
                case 1:
                    //printf("Charging Interface Extension\n");
                    ChargingInterface_t *chrg_int = NULL;
                    asn_dec_rval_t rval_chrg_int = ber_decode(NULL, &asn_DEF_ChargingInterface, (void **)&chrg_int, extensionVal_buf, extensionVal_size);
                    
                    if (rval_chrg_int.code == RC_OK) {
                        print_charging_interface(*chrg_int);
                        ASN_STRUCT_FREE(asn_DEF_ChargingInterface, chrg_int);
                    } else {
                        fprintf(stderr, "Failed to decode ChargingInterface: rval.code = %d, bytes consumed = %zu\n",
                                rval_chrg_int.code, rval_chrg_int.consumed);
                    }
                    break;
                case 2:
                    //printf("Basic Signaling Extension\n");
                    BasicSignaling_t *bsc_sgnlng = NULL;
                    asn_dec_rval_t rval_bsc_sgnlng = ber_decode(NULL, &asn_DEF_BasicSignaling, (void **)&bsc_sgnlng,
                                    extensionVal_buf, extensionVal_size);
                    
                    if (rval_bsc_sgnlng.code == RC_OK) {
                        printf("Decoded BasicSignaling extensions:\n");
                        for (int k = 0; k < bsc_sgnlng -> list.count; k++) {
                            print_basic_signaling_protocol(k, *bsc_sgnlng -> list.array[i]);
                            //printf("BasicSignalingProtocol[%zd]: %d\n", k+1, bsc_sgnlng -> list.array[i]);
                        }
                        ASN_STRUCT_FREE(asn_DEF_BasicSignaling, bsc_sgnlng);
                    } else {
                        fprintf(stderr, "Failed to decode Basic Signaling\n");
                    }
                    break;
                case 3:
                    //printf("IPv6 Socket Extension\n");
                    IPv6Socket_t *ip_socket = NULL;
                    asn_dec_rval_t rval_ip_socket = ber_decode(NULL, &asn_DEF_IPv6Socket, (void **)&ip_socket,
                                    extensionVal_buf, extensionVal_size);
                    
                    if (rval_ip_socket.code == RC_OK) {
                        printf("Decoded IPv6 Socket successfully:\n");
                        printf("    IPv6 Address: ");
                        for (size_t k = 0; k < 15; k++) {
                            printf("%02X:", ip_socket -> ipv6Address.buf[k]);
                        }
                        printf("%02X\n    TCP Port: ", ip_socket -> ipv6Address.buf[15]);
                        for (size_t k = 0; k < 3; k++) {
                            printf("%02X:", ip_socket -> tcpPort.buf[k]);
                        }
                        printf("%02X\n", ip_socket -> tcpPort.buf[3]);
                        ASN_STRUCT_FREE(asn_DEF_IPv6Socket, ip_socket);
                    } else {
                        fprintf(stderr, "   Failed to decode IPv6 Socket\n");
                    }
                    break;
                case 4:
                    //printf("High-Level Communication Extension\n");
                    HighLevelCommunication_t *hlc = NULL;
                    asn_dec_rval_t rval_hlc = ber_decode(NULL, &asn_DEF_HighLevelCommunication, (void **)&hlc,
                                    extensionVal_buf, extensionVal_size);
                    
                    if (rval_hlc.code == RC_OK) {
                        printf("Decoded HighLevelCommunication:\n");
                        for (int ii = 0; ii < hlc -> list.count; ii++) {
                            HighLevelCommunicationTuple_t *tuple = hlc -> list.array[ii];
                            printf("High Level Communication Tuple [%d]:\n", ii + 1);

                            printf("  HLC Protocol: ");
                            switch (tuple -> hlcProtocol) {
                                case HLCProtocol_din_spec_70121_2014:
                                    printf("DIN SPEC 70121:2014\n");
                                    break;
                                case HLCProtocol_iso_15118_2_2014:
                                    printf("ISO 15118-02:2014\n");
                                    break;
                                case HLCProtocol_iso_15118_20_2022:
                                    printf("ISO 15118-20:2022\n");
                                    break;
                                default:
                                    printf("Unknown (%ld)\n", tuple -> hlcProtocol);
                            }

                            for (int jj = 0; jj < tuple -> securityProfileTuple.list.count; jj++) {
                                SecurityProfileTuple_t *sp_tuple = tuple -> securityProfileTuple.list.array[jj];
                                switch (sp_tuple -> securityProfile) {
                                    case SecurityProfile_tcpOnly:
                                        printf("    Security Profiles: TCP\n");
                                        break;
                                    case SecurityProfile_tls12_server:
                                        printf("    Security Profiles: TLS 1.2 Server\n");
                                        break;
                                    case SecurityProfile_tls13_mutual:
                                        printf("    Security Profiles: TLS 1.3 Mutual\n");
                                        break;
                                    default:
                                        printf("    Security Profiles: Unknown Security profile\n");
                                }
                                
                                printf("        Authorization Methods:");
                                for (int kk = 0; kk < sp_tuple -> authorizationMethod.list.count; kk++) {
                                    AuthorizationMethod_t *auth_method = sp_tuple -> authorizationMethod.list.array[kk];
                                    switch (*auth_method) {
                                        case AuthorizationMethod_eim:
                                            printf(" EIM ");
                                            break;
                                        case AuthorizationMethod_pnc_2:
                                            printf(" PNC_ISO_15118-02 ");
                                            break;
                                        case AuthorizationMethod_pnc_20:
                                            printf(" PNC_ISO_15118-20 ");
                                            break;
                                        default:
                                            printf(" Unknown Authorization methods");
                                    }
                                }
                                printf("\n");

                                printf("        Energy Transfer Modes:");
                                for (int kk = 0; kk < sp_tuple -> energyTransferMode.list.count; kk++) {
                                    AuthorizationMethod_t *mode = sp_tuple -> energyTransferMode.list.array[kk];
                                    switch (*mode) {
                                        case EnergyTransferMode_dc:
                                            printf(" DC ");
                                            break;
                                        case EnergyTransferMode_dc_bpt:
                                            printf(" DC-BPT ");
                                            break;
                                        case EnergyTransferMode_ac:
                                            printf(" AC ");
                                            break;
                                        case EnergyTransferMode_ac_bpt:
                                            printf(" AC-BPT ");
                                            break;                                            
                                        default:
                                            printf(" Unknown Energy Transfer modes");
                                    }
                                }
                                printf("\n");
                            }
                            printf("\n");
                        }
                        ASN_STRUCT_FREE(asn_DEF_HighLevelCommunication, hlc);
                    } else {
                        fprintf(stderr, "Failed to decode HighLevelCommunication\n");
                    }
                    break;
                case 5:
                    //printf("EMSP Identifiers Extension\n");
                    EMSPIdentifiers_t *emsp = NULL;
                    asn_dec_rval_t rval_emsp = ber_decode(NULL, &asn_DEF_EMSPIdentifiers, (void **)&emsp,
                                    extensionVal_buf, extensionVal_size);
                    
                    if (rval_emsp.code == RC_OK) {
                        printf("Decoded EMSPIdentifiers:\n");
                        for (int k = 0; k < emsp -> list.count; k++) {
                            printf("    EMSP Identifier[%d]: %s\n", k+1, emsp -> list.array[k] -> buf);
                        }
                        ASN_STRUCT_FREE(asn_DEF_EMSPIdentifiers, emsp);
                    } else {
                        fprintf(stderr, "   Failed to decode EMSP Identifiers\n");
                    }
                    break;
                case 6:
                    //printf("DC Charging Limits Extension\n");
                    DCChargingLimits_t *limits = NULL;
                    asn_dec_rval_t rval_limits = ber_decode(NULL, &asn_DEF_DCChargingLimits, (void **)&limits,
                                    extensionVal_buf, extensionVal_size);
                    
                    if (rval_limits.code == RC_OK) {
                        printf("Decoded DC Charging Limits:\n");
                        printf("    Maximum Voltage: %ld [V]\n", limits -> maximumVoltage);
                        printf("    Maximum Voltage: %ld [V]\n", limits -> minimumVoltage);
                        ASN_STRUCT_FREE(asn_DEF_DCChargingLimits, limits);
                    } else {
                        printf("    Failed to decode DC Charging Limits\n");
                    }
                    break;
                case 7:
                    ConductiveChargingInterfaceLimitations_t *interface_limits = NULL;
                    asn_dec_rval_t rval_int_limits = ber_decode(NULL, &asn_DEF_ConductiveChargingInterfaceLimitations,
                                    (void **)&interface_limits, extensionVal_buf, extensionVal_size);
                    
                    if (rval_int_limits.code == RC_OK) {
                        printf("Decoded Charging Interface Limits: \n");
                        printf("    Maximum Contactor Temp: %ld [C]\n", interface_limits -> maximumContactorTemperature);
                        ASN_STRUCT_FREE(asn_DEF_ConductiveChargingInterfaceLimitations, interface_limits);
                    } else {
                        printf("    Failed to decode Conductive Charging Interface Limitations\n");
                    }
                    break;                    
                case 8:
                    EVCharacteristics_t *evChar = NULL;
                    asn_dec_rval_t rval_evChar = ber_decode(NULL, &asn_DEF_EVCharacteristics, (void **)&evChar,
                                    extensionVal_buf, extensionVal_size);

                    if(rval_evChar.code == RC_OK) {
                        printf("Decoded EV Characteristics:\n");
                        if (evChar -> vehicleIdentificationNumber -> size > 0) {
                            printf("    Vehicle Identification Number: ");
                            for (size_t i = 0; i < evChar -> vehicleIdentificationNumber -> size; i++) {
                                printf("%02X", evChar -> vehicleIdentificationNumber -> buf[i]);
                            }
                            printf("\n");
                        } else {
                            printf("    Vehicle Identification Number was NOT communicated");
                        }
                        if (evChar -> evccSoftwareVersion -> size > 0) {
                            printf("    EVCC Software Version: %.*s\n", (int)evChar -> evccSoftwareVersion -> size,
                                    evChar -> evccSoftwareVersion -> buf);
                        } else {
                            printf("    EVCC Software version was NOT communicated");
                        }
                    } else {
                        printf("    Failed to decode EV Characteristics\n");
                    }
                    break;
                case 9:
                    ChargingStationCharacteristics_t *evseChar = NULL;
                    asn_dec_rval_t rval_evseChar = ber_decode(NULL, &asn_DEF_ChargingStationCharacteristics,
                                    (void **)&evseChar, extensionVal_buf, extensionVal_size);

                    if(rval_evseChar.code == RC_OK) {
                        printf("Decoded Charging Station Characteristics:\n");
                        if (evseChar -> evseID -> size > 0) {
                            printf("    EVSE ID: ");
                            for (size_t k = 0; k < (evseChar -> evseID -> size); k++) {
                                printf("%02X",evseChar -> evseID -> buf[k]);
                            }
                            printf("\n");
                        } else {
                            printf("    EVSE ID was NOT communicated");
                        }
                        if (evseChar -> seccSoftwareVersion -> size > 0) {
                            printf("    SECC Software Version: %.*s\n", (int)evseChar -> seccSoftwareVersion -> size,
                                    evseChar -> seccSoftwareVersion -> buf);
                        } else {
                            printf("    SECC Software version was NOT communicated");
                        }
                    } else {
                        printf("Failed to decode Charging Station Characteristics\n");
                    }
                    break;
                default:
                    printf("Unknown Extension ID: %ld\n", ext -> extensionID);
                    break;
            }
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input.ber>\n", argv[0]);
        exit(1);
    }

    const char *filename = argv[1];
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Error opening file for reading");
        exit(1);
    }

    /* Read the BER file into a buffer */
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *buffer = malloc(file_size);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(fp);
        exit(1);
    }

    fread(buffer, 1, file_size, fp);
    fclose(fp);

    /* Decode the buffer into HighLevelCommunication */
    Extensions_t *extensions = calloc(1, sizeof(Extensions_t));
    asn_dec_rval_t rval = asn_decode(NULL, ATS_DER, &asn_DEF_Extensions, (void **)&extensions, buffer, file_size);
    if (rval.code != RC_OK) {
        fprintf(stderr, "Decoding failed at byte %ld\n", rval.consumed);
        ASN_STRUCT_FREE(asn_DEF_Extensions, extensions);
        exit(1);
    }

    free(buffer);

    /* Print the decoded structure */
    printf("Standardized Extensions:\n");
    print_standardized_extensions(&extensions -> standardized);

    if (extensions -> external) {
        printf("External Extensions Present\n");
    } else {
        printf("No External Extensions present\n");
    }
//    xer_fprint(stdout, &asn_DEF_Extensions, extensions);

    /* Free the allocated memory */
    ASN_STRUCT_FREE(asn_DEF_Extensions, extensions);

    return 0;
}
