# Secure Real Time Streaming

## Compile
```
mvn clean package
```

## Run
### Server
```
java -jar server/target/server-1.0.0-SNAPSHOT-jar-with-dependencies.jar movies/cars.dat 127.0.0.1 8888 <encryption_alg>
```

`encryption_alg` can be one of the following options:
- `aes` - AES-GCM
- `chacha` - ChaCha20-Poly1305
- `dprg` - Custom stream cipher from keystream generation based on AES-CTR

### Proxy

```
java -jar proxy/target/proxy-1.0.0-SNAPSHOT-jar-with-dependencies.jar <encryption_alg>
```
>`encryption_alg` uses the same options as the server.

### Video Player
#### MPV
```
client/run-mpv.sh
```

#### VLC
```
client/run-vlc.sh
```

