# VSCP Droplet

The initial plan for VSCP droplet was to build a managed flooding mesh that could self organize. This was a to large projet and we instead looked at Bluetooth BLE Mesh but everyone that have looked into this knows it is VERY complicated. Complicated is never good. We try to stick with KISS (Keep It Simple Stupid).

We decided to build VSCP droplet around the Espressif ESP-Now protocol. Even if this is developed by Espressif it should be possible to implement on other harware. The different patents taken by Espressif (https://patents.justia.com/assignee/espressif-systems-shanghai-co-ltd) probably cover some of it so be warned.

A VSCP droplet is build around three different types of nodes plus a fourth and fifth type (delta/epsilon) that is BLE based.

## (α) Alpha-nodes
Alpha-nodes have the following properties

* Wifi or Ethernet connected. Can also be USB/CAN4VSCP.
* ESP-Now.
* Use BLE for provisioning.
* OTA https or VSCP tcp/ip link protocol.
* MQTT and VSCP TCP/IP Link Protocol.
* Broadcast heartbeat every 30 seconds(Unencrypted) (RSSI/Alpha).
* Always powered.

## Initialization

Can be initialized and configured over VSCP tcp/ip link protocol. Also MQTT is setup this way.

Beta nodes can be set in bound scanning mode. Beta and gamma nodes can be unbound on command.

## (β) Beta-Nodes

Beta nodes a esp-now satellites in the mesh.

* ESP Now
* ESP Now provisioning
* ESP-Now OTA
* Long Range capable
* Broadcast heartbeat every 30 seconds(Unencrypted) (RSSI/Beta).
* Friend mode capability.
* Relay
* Have button for setup.
* Always powered

## Initialization

All beta nodes have an init button. A long press on this button bind the node to a waiting node that has been initiated to accept bounds. The binding is active for 30 seconds.

Pressing this button when a node already is bound unbound it.

### LED status
* Two color LED (Red/Green)
* Green LED is turned off for an unbound node.
* Green LED blinks while a node is bindable (30s or until bound). 
* Green LED is steady on for a bound node and blinks the number of bound nodes every twenty seconds.

### Friend node
A alpha/beta node can act as a friend for a gamma node and collect events that is intended for this node. It is important that the gamma node first tell the beta node what events it want. Default is to only get events that 
are directly addressed to the node (Level I/II protocol).

It is possible for  a Beta node to ask an alpha node for the saved events so it does not need to have local storage.

## (γ) Gamma-Nodes

Gamma nodes are the lowest level of nodes. A gamma node can connect to a beta node but othe rnodes can not connect to a gamma node.

* ESP Now
* ESP Now provisioning (button)
* ESP-Now OTA
* Can connect to **one** Beta node
* Broadcast heartbeat every 30 seconds(Unencrypted) when awake (RSSI/Alpha).
* May be on batteri.

-----

## (δ) Delta-Nodes 

* Wifi or Ethernet
* Read VSCP BLE advertising.
* Can connect to max 6 BLE devices and read/write registers of the device.
* Use BLE for provisioning.
* OTA https or VSCP tcp/ip link protocol.
* MQTT and VSCP TCP/IP Link Protocol
* Always powered.

## Initialization

All beta nodes have an init button. A long press on this button bind the node to a waiting node that has been initiated to accept bounds. The binding is active for 30 seconds.

Pressing this button when a node already is bound unbound it.

### LED status
* LED is turned off in bound/unbound node. But lit (shortly) when node wakes up.
* The LED blinks while a node is bindable (30s or until bound). 

## (Ƶ) Epsilon-Nodes

* BLE VSCP advertising.
* Battery

## Common
* Send heartbeat every 60 seconds. Battery powered node when it wakes up.
* Send RSSI every 60 seconds. Battery powered node when it wakes up.
* Send node type type (alfa/beta/gamma/delta) every minute. Part of init process.

### Init message process.

During the init process nodes communicate inmformation with each other about there capabilities.

Node inform other node of

* What node type it is (alpha/beta/gamma).
* RSSI. Periodically updated.
* How it is powered. Always on. Battery.
* Last heartbeat. RSSI. Periodically updated.