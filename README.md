# vscp-droplet

A VERY simple self forming network for wireless VSCP nodes

Warning!  
There are secure and well though out mesh networks available. Use them! 

Droplet model comes from dropping a water droplet and se the waves propagating through the water. Each event received by a node is retransmitted exactly one time if TTL > 1

## Node types

### Dumb node

- Advertising. Raw Ethernet/Multicast/UDP/BLE
- Configuration through USB/serial or similar.
- Can be encrypted
- All zones
- All subzones

### Standard node

- Advertising. Raw Ethernet/Multicast/UDP/BLE
- Receive broadcast.
- Encrypted / Non-encrypted.
- Direct BLE connectable.
- Zone
- Subzone
- Configuration through USB/serial or similar.
- Can use Friend node.

### Friend node
- Helper for 'mostly sleeping nodes'
- Advertising. Raw Ethernet/Multicast/UDP/BLE
- Receive broadcast. Collect events for friend(s).
- Act as network extension.
- Encrypted / Non-encrypted.
- Direct BLE connectable.
- Zone
- Subzone
- Configuration through USB/serial or similar.
- Can use Friend node.

### Bridge node
- Bridge between topologies.
- Advertising. Raw Ethernet/Multicast/UDP/BLE
- Receive.
- Encrypted / Non-encrypted.
- Direct BLE connectable.
- Configuration through USB/serial or similar, but also tcp/ip.
- Can use Friend node.

----

## Multicast
 - VSCP - 224.0.23.158
 - As with the other IP address classes, the entire 32 bits of the address is always used; we are just only interested in the least-significant 28 bits because the upper four bits never change.
 - Port is zone/subzone (0–65535).
 - 128-bit random key + encrypted payload.

 ## UDP
 - Always broadcast
 - Port is zone/subzone (0–65535).
 - TTL
 - 128-bit random key + encrypted payload.

 ## BLE
 - Advertising
 - zone/subzone in payload.


## Provisioning
 - Send not-provisioned broadcast message every ten seconds.


## Cryprographics modes

 - Open - no encryption
 - AES-128
 - AES-192
 - AES-256

## Discovery 
 - UDP Multicast every ten seconds to discover nodes in the surrounding area.
 - Unicast of event to found nodes in table.
 - Remove node from table if unavailable for n discoveries.

## Resend
 - Event CRC used to detect if event has been seen.
 - Turn off resend from node x/y/z for a node. Used for nearby nodes.
 - Sender strange?



# BLE

  - https://www.argenox.com/library/bluetooth-low-energy/ble-advertising-primer/
  - Advertising channels 37/38/39
  - 20ms to 10.24 seconds, in steps of 0.625ms. 0-10 ms random delay.
  - The Packet data unit for the advertising channel (called the Advertising Channel PDU) includes a 2-byte header and a variable payload from 6 to 37 bytes. The actual length of the payload is defined by the 6-bit Length field in the header of the Advertising Channel PDU.
  - ADV_IND and ADV_NONCONN_IND
  - ADV_IND is a generic advertisement and usually the most common. It’s generic in that it is not directed and it is connectable, meaning that a central device can connect to the peripheral that is advertising, and it is not directed towards a particular Central device.
  - ADV_NONCONN_IND is the advertisement type used when the peripheral does not want to accept connections, which is typical in Beacons.
  - Advertise: https://www.youtube.com/watch?v=BwGF_768B1U
  - Scan response: https://www.youtube.com/watch?v=6E4eW-lNKBE
  - Can I process OTA through Bluetooth® on ESP32?  Yes, please operate basing on bt_spp_acceptor and bt_spp_initiator. If using Bluetooth LE, please operate basing on ble_spp_server and ble_spp_client.
