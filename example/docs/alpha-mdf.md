# Standard MDF for alpha nodes

The standard register space is a level II register space that should be implemented by all alpha nodes. 

## Page 0

| Register | Access | Description |
| -------- | ------ | ----------- |
| 0 | r/w | Number of connected nodes (0-5). Writing 0 disconnect all. Writing another number has no effect. |
| 1 | r/w | Enable node binding by writing 0x55 to this register. |
| 2 | r/w | Enable/disable node VSCP tcp/ip link server. Writing a one enables and activates. Writing a zero disables. |
| 3 | r/w | Enable/disable connecting to MQTT broker. Writing a one enables and activates. Writing a zero disables. |
| 4 | r | Connection status for MQTT broker. Bit 7 - Connected. |

### Connected Nodes

Five nodes can connect to an alpha node. Entries are zeroed if an entry is unconnected. Bound nodes are always stored in order so if a node in the middle is removed nodes later to that one is moved down fill the gap.

| Register | Access | Description |
| -------- | ------ | ----------- |
| 10000 | r/w | Number of connected nodes (0-5). Writing 0 disconnect all. Writing another number has no effect. |

#### Node 0 

| Register | Access | Description |
| -------- | ------ | ----------- |
| 11000 | r/w | MAC address byte 0 of node |
| 11001 | r/w | MAC address byte 1 of node |
| 11002 | r/w | MAC address byte 2 of node |
| 11003 | r/w | MAC address byte 3 of node |
| 11004 | r/w | MAC address byte 4 of node |
| 11005 | r/w | MAC address byte 5 of node |
| 11006 | r | Node type unknown(0)/alfa(1)/beta(2)/gamma(3)/delta(4)/epsilon. |
| 11006 | r | Last RSSI of node. Value is in dBm as a signed one byte integer and zero is used for unknown. |
| 11007 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 11008 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 11009 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 1100A | r/w | Last heartbeat for node in microsceconds as a 32-bit value LSB |
| 11006 | r | Power mode for node. 0=unknown. 1=always powered. 2=battery mode medium. 3=battery mode low. 4=battery mode very low.|

#### Node 1
| Register | Access | Description |
| -------- | ------ | ----------- |
| 11100 | r/w | MAC address byte 0 of node |
| 11101 | r/w | MAC address byte 1 of node |
| 11102 | r/w | MAC address byte 2 of node |
| 11103 | r/w | MAC address byte 3 of node |
| 11104 | r/w | MAC address byte 4 of node |
| 11105 | r/w | MAC address byte 5 of node |
| 11106 | r | Node type unknown(0)/alfa(1)/beta(2)/gamma(3)/delta(4)/epsilon. |
| 11106 | r | Last RSSI of node. Value is in dBm as a signed one byte integer and zero is used for unknown. |
| 11107 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 11108 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 11109 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 1110A | r/w | Last heartbeat for node in microsceconds as a 32-bit value LSB |
| 11106 | r | Power mode for node. 0=unknown. 1=always powered. 2=battery mode medium. 3=battery mode low. 4=battery mode very low. |

#### Node 2
| Register | Access | Description |
| -------- | ------ | ----------- |
| 11200 | r/w | MAC address byte 0 of node |
| 11201 | r/w | MAC address byte 1 of node |
| 11202 | r/w | MAC address byte 2 of node |
| 11203 | r/w | MAC address byte 3 of node |
| 11204 | r/w | MAC address byte 4 of node |
| 11205 | r/w | MAC address byte 5 of node |
| 11206 | r | Node type unknown(0)/alfa(1)/beta(2)/gamma(3)/delta(4)/epsilon. |
| 11206 | r | Last RSSI of node. Value is in dBm as a signed one byte integer and zero is used for unknown. |
| 11207 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 11208 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 11209 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 1120A | r/w | Last heartbeat for node in microsceconds as a 32-bit value LSB |
| 11206 | r | Power mode for node. 0=unknown. 1=always powered. 2=battery mode medium. 3=battery mode low. 4=battery mode very low. |

#### Node 3
| Register | Access | Description |
| -------- | ------ | ----------- |
| 11300 | r/w | MAC address byte 0 of node |
| 11301 | r/w | MAC address byte 1 of node |
| 11302 | r/w | MAC address byte 2 of node |
| 11303 | r/w | MAC address byte 3 of node |
| 11304 | r/w | MAC address byte 4 of node |
| 11305 | r/w | MAC address byte 5 of node |
| 11306 | r | Node type unknown(0)/alfa(1)/beta(2)/gamma(3)/delta(4)/epsilon. |
| 11306 | r | Last RSSI of node. Value is in dBm as a signed one byte integer and zero is used for unknown. |
| 11307 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 11308 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 11309 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 1130A | r/w | Last heartbeat for node in microsceconds as a 32-bit value LSB |
| 11306 | r | Power mode for node. 0=unknown. 1=always powered. 2=battery mode medium. 3=battery mode low. 4=battery mode very low. |

#### Node 4
| Register | Access | Description |
| -------- | ------ | ----------- |
| 11400 | r/w | MAC address byte 0 of node |
| 11401 | r/w | MAC address byte 1 of node |
| 11402 | r/w | MAC address byte 2 of node |
| 11403 | r/w | MAC address byte 3 of node |
| 11404 | r/w | MAC address byte 4 of node |
| 11405 | r/w | MAC address byte 5 of node |
| 11406 | r | Node type unknown(0)/alfa(1)/beta(2)/gamma(3)/delta(4)/epsilon. |
| 11406 | r | Last RSSI of node. Value is in dBm as a signed one byte integer and zero is used for unknown. |
| 11407 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 11408 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 11409 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 1140A | r/w | Last heartbeat for node in microsceconds as a 32-bit value LSB |
| 11406 | r | Power mode for node. 0=unknown. 1=always powered. 2=battery mode medium. 3=battery mode low. 4=battery mode very low. |

#### Node 5
| Register | Access | Description |
| -------- | ------ | ----------- |
| 11500 | r/w | MAC address byte 0 of node |
| 11501 | r/w | MAC address byte 1 of node |
| 11502 | r/w | MAC address byte 2 of node |
| 11503 | r/w | MAC address byte 3 of node |
| 11504 | r/w | MAC address byte 4 of node |
| 11505 | r/w | MAC address byte 5 of node |
| 11506 | r | Node type unknown(0)/alfa(1)/beta(2)/gamma(3)/delta(4)/epsilon. |
| 11506 | r | Last RSSI of node. Value is in dBm as a signed one byte integer and zero is used for unknown. |
| 11507 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 11508 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 11509 | r/w | Last heartbeat for node in microsceconds as a 32-bit value MSB |
| 11510 | r/w | Last heartbeat for node in microsceconds as a 32-bit value LSB |
| 11511 | r | Power mode for node. 0=unknown. 1=always powered. 2=battery mode medium. 3=battery mode low. 4=battery mode very low. |


# Node IP address

## IPv4

| Register | Access | Description |
| -------- | ------ | ----------- |
| 12000 | r | Byte 0 of 32-bit IPv4 address of node (MSB) |
| 12001 | r | Byte 1 of 32-bit IPv4 address of node (MSB) |
| 12002 | r | Byte 2 of 32-bit IPv4 address of node (MSB) |
| 12003 | r | Byte 3 of 32-bit IPv4 address of node (LSB) |

## IPv6

| Register | Access | Description |
| -------- | ------ | ----------- |
| 12100 | r | Byte 0 of 128-bit IPv6 address of node (MSB) |
| 12101 | r | Byte 1 of 128-bit IPv6 address of node (MSB) |
| 12102 | r | Byte 2 of 128-bit IPv6 address of node (MSB) |
| 12103 | r | Byte 3 of 128-bit IPv6 address of node (MSB) |
| 12104 | r | Byte 4 of 128-bit IPv6 address of node (MSB) |
| 12105 | r | Byte 5 of 128-bit IPv6 address of node (MSB) |
| 12106 | r | Byte 6 of 128-bit IPv6 address of node (MSB) |
| 12107 | r | Byte 7 of 128-bit IPv6 address of node (MSB) |
| 12108 | r | Byte 8 of 128-bit IPv6 address of node (MSB) |
| 12109 | r | Byte 9 of 128-bit IPv6 address of node (MSB) |
| 12110 | r | Byte 10 of 128-bit IPv6 address of node (MSB) |
| 12111 | r | Byte 11 of 128-bit IPv6 address of node (MSB) |
| 12112 | r | Byte 12 of 128-bit IPv6 address of node (MSB) |
| 12113 | r | Byte 13 of 128-bit IPv6 address of node (MSB) |
| 12114 | r | Byte 14 of 128-bit IPv6 address of node (MSB) |
| 12115 | r | Byte 15 of 128-bit IPv6 address of node (LSB) |


# MQTT broker IP address and settings

## IPv4

| Register | Access | Description |
| -------- | ------ | ----------- |
| 12200 | r | Byte 0 of 32-bit IPv4 address of node (MSB) |
| 12201 | r | Byte 1 of 32-bit IPv4 address of node (MSB) |
| 12202 | r | Byte 2 of 32-bit IPv4 address of node (MSB) |
| 12203 | r | Byte 3 of 32-bit IPv4 address of node (LSB) |

## IPv6

| Register | Access | Description |
| -------- | ------ | ----------- |
| 12300 | r | Byte 0 of 128-bit IPv6 address of node (MSB) |
| 12301 | r | Byte 1 of 128-bit IPv6 address of node (MSB) |
| 12302 | r | Byte 2 of 128-bit IPv6 address of node (MSB) |
| 12303 | r | Byte 3 of 128-bit IPv6 address of node (MSB) |
| 12304 | r | Byte 4 of 128-bit IPv6 address of node (MSB) |
| 12305 | r | Byte 5 of 128-bit IPv6 address of node (MSB) |
| 12306 | r | Byte 6 of 128-bit IPv6 address of node (MSB) |
| 12307 | r | Byte 7 of 128-bit IPv6 address of node (MSB) |
| 12308 | r | Byte 8 of 128-bit IPv6 address of node (MSB) |
| 12309 | r | Byte 9 of 128-bit IPv6 address of node (MSB) |
| 12310 | r | Byte 10 of 128-bit IPv6 address of node (MSB) |
| 12311 | r | Byte 11 of 128-bit IPv6 address of node (MSB) |
| 12312 | r | Byte 12 of 128-bit IPv6 address of node (MSB) |
| 12313 | r | Byte 13 of 128-bit IPv6 address of node (MSB) |
| 12314 | r | Byte 14 of 128-bit IPv6 address of node (MSB) |
| 12315 | r | Byte 15 of 128-bit IPv6 address of node (LSB) |

## Port

| Register | Access | Description |
| -------- | ------ | ----------- |
| 12400 | r | MQTT broker port (MSB) |
| 12401 | r | MQTT broker port (MSB) |


## User

Can be 16-bytes. Must be null terminated if less.

| Register | Access | Description |
| -------- | ------ | ----------- |
| 12500 - 12515 | r/w | User name for MQTT broker connection byte 0-15 |



## Password

Can be 16-bytes. Must be null terminated if less. Can only be written not read.

| Register | Access | Description |
| -------- | ------ | ----------- |
| 12600 - 12615 | w | Password for MQTT broker connection byte 0-15. |




## Publish topic

Can be 32-bytes. Must be null terminated if less.

| Register | Access | Description |
| -------- | ------ | ----------- |
| 12700 - 12631 | r/w | Publish topic. |

## Subscribe topics

Can each be 32-bytes. Must be null terminated if less. A maximum of eight topics can be subscribed to.

### Subscribe topic 0

| Register | Access | Description |
| -------- | ------ | ----------- |
| 13000 - 13031 | r/w | Subscribe topic. |

### Subscribe topic 1

| Register | Access | Description |
| -------- | ------ | ----------- |
| 13100 - 13131 | r/w | Subscribe topic. |

### Subscribe topic 2

| Register | Access | Description |
| -------- | ------ | ----------- |
| 13200 - 13231 | r/w | Subscribe topic. |

### Subscribe topic 3

| Register | Access | Description |
| -------- | ------ | ----------- |
| 13300 - 13331 | r/w | Subscribe topic. |

### Subscribe topic 4

| Register | Access | Description |
| -------- | ------ | ----------- |
| 13400 - 13431 | r/w | Subscribe topic. |

### Subscribe topic 5

| Register | Access | Description |
| -------- | ------ | ----------- |
| 13500 - 13531 | r/w | Subscribe topic. |

### Subscribe topic 6

| Register | Access | Description |
| -------- | ------ | ----------- |
| 13600 - 13631 | r/w | Subscribe topic. |

### Subscribe topic 7

| Register | Access | Description |
| -------- | ------ | ----------- |
| 13700 - 13731 | r/w | Subscribe topic. |



