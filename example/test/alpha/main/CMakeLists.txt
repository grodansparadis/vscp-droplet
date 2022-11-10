idf_component_register(SRCS "espnow_alpha_main.c" "vscp_espnow.c"
                    INCLUDE_DIRS "." "$ENV{VSCP_COMMON}" "$ENV{VSCP_ROOT}")
