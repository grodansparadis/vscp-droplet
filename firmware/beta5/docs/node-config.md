# node configuration

Beta and Gamma nodes have a unique 16 byte secret key stored. This secret key is used to encrypt certain frames using AES-128.

## Init request

When the init button is pressed on a a Beta or Gamma node it broadcast an **init-request event**. This request is sent unencrypted and it's purpose is to get the system key for a droplet segment which will be used for protection of all further frames sent and received after it has been set.

The init state lasts for 30 seconds or until the node receive the common system secret key.

When the node receives the common system secret key it send out **init-request-ok** event encrypted with the system key.

From this point it is possible to configure the node by writing it's registers.

### Alternative way to initiate init.

The init request can also be initiated by and alpha node. The alpha node in this case must know the mac address and the secret of the node and the start init request is encrypted using this secret.

