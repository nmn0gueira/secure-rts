# Secure Real Time Streaming

## Compile
```
mvn clean compile package -DskipTests
```

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

