idf_component_register(SRCS "button_adc.c" "button_gpio.c" "button.c"
                        INCLUDE_DIRS include
                        PRIV_REQUIRES esp_adc_cal)
