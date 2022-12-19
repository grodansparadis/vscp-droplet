# Droplet 

The Droplet protocol is a managed broadcast protocol that is used to send raw 802.11 frames that carry VSCP events.

The protocol defines three types of nodes. Alpha, Beta and Gamma. Where Alpha nodes are the most capable and beta nodes are the least capable.

On ESP32 devices the Espressif developed **esp-now** protocol is used for the raw frames.

There is now garanties that a frame will be delivered to it's destination. This must be handled in the application as always with VSCP. Many events like the VSCP read register will handle this by it's design as it requires a response. But for other a resonable response mechanism must be set up.

## Alpha nodes (α)
* Always powered.
* Always awake.
* ESP Now
* Init button. Long press, Set factory defaults.
* Two color status led.
* Wifi (STA) or Ethernet.
* BLE provisioning.
* OTA https or uppload.
* VSCP TCP/IP Link Protocol / MQTT.
* Can set up alpha and beta.
* Web interface.
* Long Range capable (500 meters).
* Registers.
* DM.

## Beta nodes (β)
* Always powered.
* Always awake.
* ESP Now
* ESP Now provisioning
* ESP-Now OTA
* Init button. Press - Init 30 seconds. Long press - Set factory defaults.
* Two color status led.
* Can hold events for gamma nodes attached to it.
* Long Range capable (500 meters).
* Registers.
* DM.

## Gamma nodes (γ)
* Battery powered.
* Mostly sleeping.
* ESP Now.
* Init button. Press - Init 30 seconds. Long press - Set factory defaults.
* Two color status led.
* Long Range capable (500 meters).
* Registers.
* DM.


## Frame format

Even if VSCP Level II events are used for the Droplet protocol, which can hold 512 bytes at it's maximum, only 128 bytes is allowed when sending events in Droplet. 

The packet format is as follows.

| Type | Size (bytes) | Description |
| ---- | ------------ | ----------- | 
| **pktid** |  1  | Low nibble: Encryption. 0= no encryption. 1 =AES-128, 2=AES-192. 3=AES-256. High nibble: Node type sending frame. 0=alpha, 1=beta, 2 = gamma) |
| **ttl** |  1  | Time to live |
| **magic** |  2  | Random numbe rused for cache |
| **dest-addr** |  6  | Destination address |
| **Head** |  2  | VSCP head bytes |
| **node-id/nickname** |  2  | Id for node (combined with mac) |
| **VSCP class** |  2  | The VSCP class |
| **VSCP type** |  2  | The VSCP type |
| **size** |  1  | Data len (needed as encryption can pad data) |
| **VSCP data** |  0-128 | Data for VSCP frame. Max 218 (espnow: 230) bytes  | 

  - Min packet is 19 bytes.
  - Max packet is (147) 19 + 128 bytes.

when the frame is encrypted it is sent as

**| type | Encrypted data | iv (16) |**

**Type** is the encrypted byte from above. It is never encrypted.

The encrypted data is from ttl up to and including data.

At the end of the encrypted frame is a 16 byte IV attached. The IV and the common key is used to de3crypt the encrypted part ofr the frame at the receiver side.
