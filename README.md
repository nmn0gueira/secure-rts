# Secure Real Time Streaming

## Structure

```
secure-rts/
├── lib/                         # Shared library
│   └── src/main/java/
│       ├── common/              # Utility functions
│       ├── crypto/              # Cipher suites, integrity checks, PKI utilities
│       ├── datagram/            # RTSSP secure datagram framing (Part 1)
│       └── shp/                 # SHP handshake protocol (Part 2)
├── server/                      # Streams .dat files over secure UDP
│   ├── crypto/                  # Per-movie crypto configs (Part 1)
│   ├── suites/                  # Per-movie cipher suite lists (Part 2)
│   └── src/main/java/server/
│       ├── Part1Main.java
│       └── Part2Main.java
├── proxy/                       # Receives stream, decrypts, forwards to media player
│   ├── crypto/                  # Per-movie crypto configs (Part 1)
│   ├── cipher-suites.conf       # Advertised cipher suites (Part 2)
│   └── src/main/java/proxy/
│       ├── Part1Main.java
│       └── Part2Main.java
├── client/                      # Media player launch scripts (VLC / MPV)
├── scripts/                     # PKI setup (generate-shp-stores.sh)
└── STRUCTURE.md                 # Full file-by-file breakdown by part
```

## Build
```
mvn clean package -DskipTests
```

## Setup (Part 2)
```
bash scripts/generate-shp-stores.sh
```

## Run

### Part 1
```
java -cp server/target/server-jar-with-dependencies.jar server.Part1Main <multicast-addr> <multicast-port> <tcp-port>
java -cp proxy/target/proxy-jar-with-dependencies.jar proxy.Part1Main <server-host> <tcp-port> <movie>
```

### Part 2
```
java -cp server/target/server-jar-with-dependencies.jar server.Part2Main <multicast-addr> <shp-port>
java -cp proxy/target/proxy-jar-with-dependencies.jar proxy.Part2Main <server-host> <shp-port> <movie>
```

### Media player
```
client/run-mpv.sh   
```
or
```
client/run-vlc.sh
```
