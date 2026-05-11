# Secure Real Time Streaming

## Compile
```
mvn clean compile package -DskipTests
```

## Generate local SHP certificates
The generated stores are local artefacts and should not be committed. They are written to `local/shp-stores`.

```
bash scripts/generate-shp-stores.sh
```

Use `--force` to regenerate existing stores.

## Run
### Server
```
java -jar server/target/server-1.0.0-SNAPSHOT-jar-with-dependencies.jar movies/cars.dat 127.0.0.1 8888
```

### Proxy

```
java -jar proxy/target/proxy-1.0.0-SNAPSHOT-jar-with-dependencies.jar
```

### Video Player
#### MPV
```
client/run-mpv.sh
```

#### VLC
```
client/run-vlc.sh
```

