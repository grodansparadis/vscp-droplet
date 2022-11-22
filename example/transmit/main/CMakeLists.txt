idf_component_register(SRCS "main.c" 
                            "~/development/VSCP/vscp-firmware/common/vscp-firmware-helper.c"
                            "~/development/VSCP/vscp-firmware/common/vscp-firmware-level2.c"
                            "websrv.c"
                            "vscp_espnow.c"
                            "wifiprov.c"

                    INCLUDE_DIRS "." 
                                  "$ENV{VSCP_COMMON}" 
                                  "$ENV{VSCP_ROOT}"
                                  "$ENV{VSCP_FIRMWARE_COMMON}")
