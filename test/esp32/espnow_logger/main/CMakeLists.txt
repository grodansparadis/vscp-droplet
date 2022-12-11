idf_component_register(SRCS "espnow_logger.c"
                            "../../../../firmware/alpha5/main/vscp-droplet.c"  
                    INCLUDE_DIRS "." 
                                  "$ENV{VSCP_COMMON}" 
                                  "$ENV{VSCP_ROOT}"
                                  "$ENV{VSCP_FIRMWARE_COMMON}"
                                  "../../../../firmware/alpha5/main/")
