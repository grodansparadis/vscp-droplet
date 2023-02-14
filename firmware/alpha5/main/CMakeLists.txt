idf_component_register(SRCS "main.c" 
                            "$ENV{VSCP_FIRMWARE_COMMON}/vscp-firmware-helper.c"
                            "$ENV{VSCP_FIRMWARE_COMMON}/vscp-firmware-level2.c"
                            "$ENV{VSCP_FIRMWARE_COMMON}/vscp-link-protocol.c"
                            "$ENV{VSCP_FIRMWARE_COMMON}/vscp-aes.c"
                            "../../common/led_indicator.c"
                            "../../common/button.c"
                            "../../common/button-gpio.c"
                            "urldecode.c"
                            "websrv.c"
                            "../../common/vscp-droplet.c"
                            "wifiprov.c"
                            "tcpsrv.c"
                            "callbacks-link.c"
                            "callbacks-vscp-protocol.c"
                            "mqtt.c"
                            "net_logging.c"
                            "udp_logging.c"
                            "tcp_logging.c"
                            "mqtt_logging.c"
                            "http_logging.c"
                            

                    INCLUDE_DIRS "." 
                                  "../../common"
                                  "$ENV{VSCP_COMMON}" 
                                  "$ENV{VSCP_ROOT}"
                                  "$ENV{VSCP_FIRMWARE_COMMON}"

                    EMBED_TXTFILES ${project_dir}/server_certs/ca_cert.pem
                                   ${project_dir}/server_certs/mqtt_eclipse_io.pem
            )
