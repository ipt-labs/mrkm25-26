# Lab3

## Authors

Bondarenko Oleksii (FB-41mn), Kryhin Dmytro (FB-41mn)

## Setup

```shell
pip3 install poetry
./setup.sh
```

## Run

```shell
./run.sh
```

## Usage example

### Generate keys

```shell
curl -s http://127.0.0.1:5000/generate_keys -o keys.zip
```

```shell
unzip keys.zip
```

### Sign message

```shell
echo "This is the message to sign" > message.txt
```

```shell
curl -s -X POST http://127.0.0.1:5000/sign \           
     -F "privkey=@privkey.pem" \
     -F "message=@message.txt" \
     -o signature.bin
```

### Verify message

```shell
curl -X POST http://127.0.0.1:5000/verify \
     -F "pubkey=@pubkey.pem" \
     -F "message=@message.txt" \
     -F "signature=@signature.bin"
```

