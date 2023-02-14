idf_component_register(SRCS "main.c" 
                            "$ENV{VSCP_FIRMWARE_COMMON}/vscp-firmware-helper.c"
                            "$ENV{VSCP_FIRMWARE_COMMON}/vscp-firmware-level2.c"
                            "$ENV{VSCP_FIRMWARE_COMMON}/vscp-aes.c"
                            "../../common/led_indicator.c"
                            "../../common/button.c"
                            "../../common/button-gpio.c"
                            "../../common/vscp-droplet.c"
                            "callbacks-vscp-protocol.c"                            

                    INCLUDE_DIRS "." 
                                  "../../common"
                                  "$ENV{VSCP_COMMON}" 
                                  "$ENV{VSCP_ROOT}"
                                  "$ENV{VSCP_FIRMWARE_COMMON}"

            )
