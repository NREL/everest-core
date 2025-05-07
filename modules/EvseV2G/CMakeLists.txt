#
# AUTO GENERATED - MARKED REGIONS WILL BE KEPT
# template version 3
#

# module setup:
#   - ${MODULE_NAME}: module name
ev_setup_cpp_module()

# ev@bcc62523-e22b-41d7-ba2f-825b493a3c97:v1
# insert your custom targets and additional config variables here
option(USING_MBED_TLS "Use MbedTLS for V2G" OFF)

if(USING_MBED_TLS)
target_compile_definitions(${MODULE_NAME} PRIVATE
    EVEREST_MBED_TLS
)
endif()
# ev@bcc62523-e22b-41d7-ba2f-825b493a3c97:v1

target_sources(${MODULE_NAME}
    PRIVATE
        "charger/ISO15118_chargerImpl.cpp"
)

# ev@c55432ab-152c-45a9-9d2e-7281d50c69c3:v1
# Add pkg-config functionality
find_package(PkgConfig REQUIRED)

# search for libevent.pc
pkg_search_module(EVENT REQUIRED libevent)

target_include_directories(${MODULE_NAME} PRIVATE
    crypto
    connection
    asn1
)

add_library(asn1_modules
	asn1/ANY_aper.c
	asn1/ANY_ber.c
	asn1/ANY.c
	asn1/ANY_jer.c
	asn1/ANY_uper.c
	asn1/ANY_xer.c
	asn1/aper_decoder.c
	asn1/aper_encoder.c
	asn1/aper_opentype.c
	asn1/aper_support.c
	asn1/asn_application.c
	asn1/asn_bit_data.c
	asn1/asn_codecs_prim_ber.c
	asn1/asn_codecs_prim.c
	asn1/asn_codecs_prim_jer.c
	asn1/asn_codecs_prim_xer.c
	asn1/asn_internal.c
	asn1/asn_random_fill.c
	asn1/asn_SEQUENCE_OF.c
	asn1/asn_SET_OF.c
	asn1/AuthorizationMethod.c
	asn1/BasicSignaling.c
	asn1/BasicSignalingProtocol.c
	asn1/ber_decoder.c
	asn1/ber_tlv_length.c
	asn1/ber_tlv_tag.c
	asn1/BIT_STRING.c
	asn1/BIT_STRING_jer.c
	asn1/BIT_STRING_oer.c
	asn1/BIT_STRING_print.c
	asn1/BIT_STRING_rfill.c
	asn1/BIT_STRING_uper.c
	asn1/BIT_STRING_xer.c
	asn1/BOOLEAN_aper.c
	asn1/BOOLEAN_ber.c
	asn1/BOOLEAN.c
	asn1/BOOLEAN_jer.c
	asn1/BOOLEAN_oer.c
	asn1/BOOLEAN_print.c
	asn1/BOOLEAN_rfill.c
	asn1/BOOLEAN_uper.c
	asn1/BOOLEAN_xer.c
	asn1/ChargingInterface.c
	asn1/ChargingStationCharacteristics.c
	asn1/ConductiveChargingInterfaceLimitations.c
	asn1/constraints.c
	asn1/constr_CHOICE_aper.c
	asn1/constr_CHOICE_ber.c
	asn1/constr_CHOICE.c
	asn1/constr_CHOICE_jer.c
	asn1/constr_CHOICE_oer.c
	asn1/constr_CHOICE_print.c
	asn1/constr_CHOICE_rfill.c
	asn1/constr_CHOICE_uper.c
	asn1/constr_CHOICE_xer.c
	asn1/constr_SEQUENCE_aper.c
	asn1/constr_SEQUENCE_ber.c
	asn1/constr_SEQUENCE.c
	asn1/constr_SEQUENCE_jer.c
	asn1/constr_SEQUENCE_oer.c
	asn1/constr_SEQUENCE_OF_aper.c
	asn1/constr_SEQUENCE_OF_ber.c
	asn1/constr_SEQUENCE_OF.c
	asn1/constr_SEQUENCE_OF_jer.c
	asn1/constr_SEQUENCE_OF_uper.c
	asn1/constr_SEQUENCE_OF_xer.c
	asn1/constr_SEQUENCE_print.c
	asn1/constr_SEQUENCE_rfill.c
	asn1/constr_SEQUENCE_uper.c
	asn1/constr_SEQUENCE_xer.c
	asn1/constr_SET_OF_aper.c
	asn1/constr_SET_OF_ber.c
	asn1/constr_SET_OF.c
	asn1/constr_SET_OF_jer.c
	asn1/constr_SET_OF_oer.c
	asn1/constr_SET_OF_print.c
	asn1/constr_SET_OF_rfill.c
	asn1/constr_SET_OF_uper.c
	asn1/constr_SET_OF_xer.c
	asn1/constr_TYPE.c
	asn1/DCChargingLimits.c
	asn1/der_encoder.c
	asn1/EMSPIdentifier.c
	asn1/EMSPIdentifiers.c
	asn1/EnergyTransferMode.c
	asn1/ENUMERATED_aper.c
	asn1/ENUMERATED.c
	asn1/ENUMERATED_jer.c
	asn1/ENUMERATED_oer.c
	asn1/ENUMERATED_uper.c
	asn1/EVCharacteristics.c
	asn1/Extensions.c
	asn1/EXTERNAL.c
	asn1/ExternalExtension.c
	asn1/ExternalExtensions.c
	asn1/GraphicString.c
	asn1/HighLevelCommunication.c
	asn1/HighLevelCommunicationTuple.c
	asn1/HLCProtocol.c
	asn1/INTEGER_aper.c
	asn1/INTEGER_ber.c
	asn1/INTEGER.c
	asn1/INTEGER_jer.c
	asn1/INTEGER_oer.c
	asn1/INTEGER_print.c
	asn1/INTEGER_rfill.c
	asn1/INTEGER_uper.c
	asn1/INTEGER_xer.c
	asn1/IPv6Socket.c
	asn1/jer_decoder.c
	asn1/jer_encoder.c
	asn1/jer_support.c
	asn1/NativeEnumerated_aper.c
	asn1/NativeEnumerated.c
	asn1/NativeEnumerated_jer.c
	asn1/NativeEnumerated_oer.c
	asn1/NativeEnumerated_uper.c
	asn1/NativeEnumerated_xer.c
	asn1/NativeInteger_aper.c
	asn1/NativeInteger_ber.c
	asn1/NativeInteger.c
	asn1/NativeInteger_jer.c
	asn1/NativeInteger_oer.c
	asn1/NativeInteger_print.c
	asn1/NativeInteger_rfill.c
	asn1/NativeInteger_uper.c
	asn1/NativeInteger_xer.c
	asn1/ObjectDescriptor.c
	asn1/OBJECT_IDENTIFIER.c
	asn1/OBJECT_IDENTIFIER_jer.c
	asn1/OBJECT_IDENTIFIER_print.c
	asn1/OBJECT_IDENTIFIER_rfill.c
	asn1/OBJECT_IDENTIFIER_xer.c
	asn1/OCTET_STRING_aper.c
	asn1/OCTET_STRING_ber.c
	asn1/OCTET_STRING.c
	asn1/OCTET_STRING_jer.c
	asn1/OCTET_STRING_oer.c
	asn1/OCTET_STRING_print.c
	asn1/OCTET_STRING_rfill.c
	asn1/OCTET_STRING_uper.c
	asn1/OCTET_STRING_xer.c
	asn1/oer_decoder.c
	asn1/oer_encoder.c
	asn1/oer_support.c
	asn1/OPEN_TYPE_aper.c
	asn1/OPEN_TYPE_ber.c
	asn1/OPEN_TYPE.c
	asn1/OPEN_TYPE_jer.c
	asn1/OPEN_TYPE_oer.c
	asn1/OPEN_TYPE_uper.c
	asn1/OPEN_TYPE_xer.c
	asn1/per_decoder.c
	asn1/per_encoder.c
	asn1/per_opentype.c
	asn1/per_support.c
	asn1/SecurityProfile.c
	asn1/SecurityProfileTuple.c
	asn1/StandardizedExtension.c
	asn1/StandardizedExtensions.c
	asn1/uper_decoder.c
	asn1/uper_encoder.c
	asn1/uper_opentype.c
	asn1/uper_support.c
	asn1/UTF8String.c
	asn1/UTF8String_print.c
	asn1/UTF8String_rfill.c
	asn1/xer_decoder.c
	asn1/xer_encoder.c
	asn1/xer_support.c
)

target_include_directories(asn1_modules PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/asn1)

target_link_libraries(${MODULE_NAME} PUBLIC ${EVENT_LIBRARIES} -levent -lpthread -levent_pthreads)

target_link_libraries(${MODULE_NAME}
    PRIVATE
        cbv2g::din
        cbv2g::iso2
        cbv2g::tp
        asn1_modules
)

target_sources(${MODULE_NAME}
    PRIVATE
        "connection/connection.cpp"
        "iso_server.cpp"
        "din_server.cpp"
        "log.cpp"
        "sdp.cpp"
        "tools.cpp"
        "v2g_ctx.cpp"
        "v2g_server.cpp"
)

if(USING_MBED_TLS)
# needed for header file enum definition
target_include_directories(${MODULE_NAME} PRIVATE
        ../../lib/staging/tls ../../lib/staging/util
)
target_link_libraries(${MODULE_NAME}
    PRIVATE
        mbedcrypto
        mbedtls
        mbedx509
)
target_sources(${MODULE_NAME}
    PRIVATE
        "crypto/crypto_mbedtls.cpp"
)
else()
target_link_libraries(${MODULE_NAME}
    PRIVATE
        everest::tls
)
target_sources(${MODULE_NAME}
    PRIVATE
        "crypto/crypto_openssl.cpp"
        "connection/tls_connection.cpp"
)
endif()

if(EVEREST_CORE_BUILD_TESTING)
    add_subdirectory(tests)
endif()
# ev@c55432ab-152c-45a9-9d2e-7281d50c69c3:v1
