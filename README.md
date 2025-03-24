# nodekey-tools

**Note:** This is still a work in progress. Use at your own risk and only for testing purposes.

A collection of tools for generating and managing Ethereum node keys (secp256k1), with a focus on DAS (Data Availability Sampling) column custody.

## Usage

The easiest way to use the tool is to just use it via docker:

```bash
docker run --rm -it ghcr.io/ethpandaops/nodekey-tools:master --help
```

### Generate a random node key

```bash
nodekey-tools generate
```

### Generate a node key for specific DAS columns

```bash
nodekey-tools generate --das-columns 1,2,3
```

### Show information (pubkey, node id, DAS columns, etc.)
From private key:

```bash
$ nodekey-tools info --priv-key 000bbc3112bd249176b12e0f40ecaa1ec2c6b89e8b6d9cd244e609693a891b7b
```

From node ID:

```bash
$ nodekey-tools info --node-id e23005d5754cb0c4ca88ba99a8462e31ba8ae7b57f585db73a4b0dacd2415c1b --custody-column-count 8

# Output
+---------------------+------------------------------------------------------------------+
|        FIELD        |                              VALUE                               |
+---------------------+------------------------------------------------------------------+
| Node ID             | e23005d5754cb0c4ca88ba99a8462e31ba8ae7b57f585db73a4b0dacd2415c1b |
+---------------------+------------------------------------------------------------------+
| DAS Custody Columns | [55, 61, 65, 82, 90, 108, 111, 124]                              |
+---------------------+------------------------------------------------------------------+

```

### Convert a hex secp256k1 private key to different formats

Depending on your consensus layer client, you might need one format or the other. Below is a table of the expected format for each client:

Client | File location | Additional flags | Key format
--- | --- | --- | ---
Lighthouse | `$DATADIR/beacon/network/key` |  | binary
Grandine | `$DATADIR/network/key` | | binary
Nimbus |  | `--netkey-file=$PATH_TO_KEY --insecure-netkey-password` | keystore
Lodestar | `$DATADIR/peer-id.json` | | libp2p
Teku |  | `--Xp2p-private-key-file-secp256k1=$PATH_TO_KEY` | hex
Prysm |  | `--p2p-priv-key=$PATH_TO_KEY` | hex



#### binary

```bash
$ nodekey-tools convert-secp256k1 --output-format binary --key 000bbc3112bd249176b12e0f40ecaa1ec2c6b89e8b6d9cd244e609693a891b7b --output-file key.bin

# Output file
$ cat key.bin | xxd -p -c256
000bbc3112bd249176b12e0f40ecaa1ec2c6b89e8b6d9cd244e609693a891b7b
```

#### libp2p
```bash
$ nodekey-tools convert-secp256k1 --output-format libp2p --key 000bbc3112bd249176b12e0f40ecaa1ec2c6b89e8b6d9cd244e609693a891b7b --output-file key.libp2p.json

# Output file
$ cat key.libp2p.json
{
  "id": "16Uiu2HAm9hPUmSZbyoRjQvF7T1MGh5XNYPNPcSZsrHtDBpib5PW2",
  "pubKey": "CAISIQLUCkC2vbakeqSY6TdJqTSmpshGPaR/Q3qzWHzInIzzyw==",
  "privKey": "CAISIAALvDESvSSRdrEuD0Dsqh7Cxriei22c0kTmCWk6iRt7"
}
```

#### keystore
This format is prefered by Nimbus. Note, that on Nimbus you can provide the `--insecure-netkey-password` flag, which will use `INSECUREPASSWORD` as the password for the keystore file encryption. Otherwise Nimbus will prompt you for the keystore password when it runs. If you need to generate the keystore with a different password, you can do this via the `--keystore-password` flag.

```bash
$ nodekey-tools convert-secp256k1 --output-format keystore --key 000bbc3112bd249176b12e0f40ecaa1ec2c6b89e8b6d9cd244e609693a891b7b --output-file key.keystore.json

# Output file
$ cat key.keystore.json
{
  "crypto": {
    "kdf": {
      "function": "scrypt",
      "params": {
        "dklen": 32,
        "n": 262144,
        "p": 1,
        "r": 8,
        "salt": "30394f01359a1ef72723295cacc448b65499d775ae731f91df742ce2733fe44a"
      },
      "message": ""
    },
    "checksum": {
      "function": "sha256",
      "params": {},
      "message": "391df780251bcb57fa10b5679f08e99d92dd59695b077c80d6dd559fb57b2b48"
    },
    "cipher": {
      "function": "aes-128-ctr",
      "params": {
        "iv": "290d492a891cfa203592a4ce85765cf7"
      },
      "message": "b47507de06419e1986dfc1dcddf79d58efbebda87d638f98c8bd1b290f8cebe5fa18eb70"
    }
  },
  "pubkey": "0802122102d40a40b6bdb6a47aa498e93749a934a6a6c8463da47f437ab3587cc89c8cf3cb",
  "uuid": "2e00d87c-7fe9-4998-9243-7454195508f2",
  "version": 1
}
```



### Generate nodekeys for a DAS network

This command is useful to generate nodekeys for a DAS network. It will try to generate a set of nodekeys that are evenly distributed across the DAS columns.

This will generate 18 nodekeys across a 128 column network and save them to the `result.json` file.

```bash
# Try 18 nodes first. This should be quite fast to generate.
$ nodekey-tools generate-network --node-count 18 --column-count 128 --output-file result-18.json

# If you want the "pefect" size of 16 (128 columns / 8 columns per node), so that each column is
# served by a single node,  then you can run the following command.
# Note that this can take hours/days. ( ~ 10 days when mining 4 million keys/sec ).
$ nodekey-tools generate-network --node-count 16 --column-count 128 --output-file result-16.json
```

### Show information about a generated network based on the JSON file

```bash
$ nodekey-tools info-network --input-file result-16.json

# Output
Loaded network information for 16 nodes from result-16.json

Column Coverage Table:
=====================
+------+----------+    +------+----------+    +------+----------+    +------+----------+
| Col  | Nodes    |    | Col  | Nodes    |    | Col  | Nodes    |    | Col  | Nodes    |
+------+----------+    +------+----------+    +------+----------+    +------+----------+
| 0    | 12       |    | 32   | 6        |    | 64   | 15       |    | 96   | 16       |
| 1    | 15       |    | 33   | 6        |    | 65   | 14       |    | 97   | 7        |
| 2    | 6        |    | 34   | 12       |    | 66   | 3        |    | 98   | 9        |
| 3    | 7        |    | 35   | 2        |    | 67   | 15       |    | 99   | 4        |
| 4    | 13       |    | 36   | 12       |    | 68   | 11       |    | 100  | 16       |
| 5    | 6        |    | 37   | 14       |    | 69   | 3        |    | 101  | 2        |
| 6    | 11       |    | 38   | 10       |    | 70   | 3        |    | 102  | 16       |
| 7    | 14       |    | 39   | 12       |    | 71   | 14       |    | 103  | 1        |
| 8    | 10       |    | 40   | 8        |    | 72   | 13       |    | 104  | 16       |
| 9    | 4        |    | 41   | 9        |    | 73   | 13       |    | 105  | 4        |
| 10   | 5        |    | 42   | 8        |    | 74   | 7        |    | 106  | 16       |
| 11   | 12       |    | 43   | 9        |    | 75   | 11       |    | 107  | 2        |
| 12   | 14       |    | 44   | 11       |    | 76   | 1        |    | 108  | 13       |
| 13   | 7        |    | 45   | 14       |    | 77   | 3        |    | 109  | 11       |
| 14   | 5        |    | 46   | 15       |    | 78   | 2        |    | 110  | 11       |
| 15   | 13       |    | 47   | 9        |    | 79   | 10       |    | 111  | 5        |
| 16   | 3        |    | 48   | 7        |    | 80   | 2        |    | 112  | 10       |
| 17   | 1        |    | 49   | 6        |    | 81   | 11       |    | 113  | 1        |
| 18   | 6        |    | 50   | 7        |    | 82   | 4        |    | 114  | 2        |
| 19   | 15       |    | 51   | 1        |    | 83   | 6        |    | 115  | 3        |
| 20   | 15       |    | 52   | 1        |    | 84   | 14       |    | 116  | 4        |
| 21   | 15       |    | 53   | 8        |    | 85   | 5        |    | 117  | 1        |
| 22   | 10       |    | 54   | 9        |    | 86   | 5        |    | 118  | 1        |
| 23   | 16       |    | 55   | 13       |    | 87   | 8        |    | 119  | 7        |
| 24   | 2        |    | 56   | 9        |    | 88   | 13       |    | 120  | 8        |
| 25   | 3        |    | 57   | 3        |    | 89   | 8        |    | 121  | 7        |
| 26   | 12       |    | 58   | 8        |    | 90   | 5        |    | 122  | 2        |
| 27   | 12       |    | 59   | 16       |    | 91   | 10       |    | 123  | 4        |
| 28   | 13       |    | 60   | 10       |    | 92   | 9        |    | 124  | 15       |
| 29   | 11       |    | 61   | 5        |    | 93   | 10       |    | 125  | 4        |
| 30   | 4        |    | 62   | 8        |    | 94   | 6        |    | 126  | 5        |
| 31   | 14       |    | 63   | 9        |    | 95   | 12       |    | 127  | 16       |
+------+----------+    +------+----------+    +------+----------+    +------+----------+
```

## License

This project is licensed under the GPL-3.0 license. See the [LICENSE](LICENSE) file for details.
