idf_component_register(SRCS "main.c" 
                            "$ENV{VSCP_FIRMWARE_COMMON}/vscp-firmware-helper.c"
                            "$ENV{VSCP_FIRMWARE_COMMON}/vscp-firmware-level2.c"
                            "$ENV{VSCP_FIRMWARE_COMMON}/vscp-link-protocol.c"
                            "websrv.c"
                            "vscp_espnow.c"
                            "wifiprov.c"
                            "tcpsrv.c"
                            "callbacks-link.c"
                            "callbacks-vscp-protocol.c"

                    INCLUDE_DIRS "." 
                                  "$ENV{VSCP_COMMON}" 
                                  "$ENV{VSCP_ROOT}"
                                  "$ENV{VSCP_FIRMWARE_COMMON}"

                    EMBED_TXTFILES ${project_dir}/server_certs/ca_cert.pem              
            )
