idf_component_register(SRCS "button_adc.c" "button_gpio.c" "iot_button.c"
                        INCLUDE_DIRS include
                        REQUIRES driver
                        PRIV_REQUIRES esp_adc_cal esp_timer)
