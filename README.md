# nodekey-tools

**Note:** This is still a work in progress. Use at your own risk and only for testing purposes.

A collection of tools for generating and managing Ethereum node keys, with a focus on DAS (Data Availability Sampling) column custody.

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

### Show information (pubkey, node id, DAS columns, etc.) about a node

From private key:

```bash
nodekey-tools info --priv-key 000bbc3112bd249176b12e0f40ecaa1ec2c6b89e8b6d9cd244e609693a891b7b
```

From node id:

```bash
nodekey-tools info --node-id e23005d5754cb0c4ca88ba99a8462e31ba8ae7b57f585db73a4b0dacd2415c1b
```


### Generate nodekeys for a DAS network

This command is useful to generate nodekeys for a DAS network. It will try to generate a set of nodekeys that are evenly distributed across the DAS columns.

This will generate 18 nodekeys across a 128 column network and save them to the `result.json` file.

```bash
nodekey-tools generate-network --node-count 18 --column-count 128 --output-file result.json
```
