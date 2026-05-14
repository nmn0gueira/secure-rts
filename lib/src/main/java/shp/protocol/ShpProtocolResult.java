package shp.protocol;

import shp.ShpMessage;

import java.util.Optional;

public record ShpProtocolResult(Optional<ShpMessage> response, State state) {

    public static ShpProtocolResult error() {
        return new ShpProtocolResult(Optional.empty(), State.ERROR);
    }

    public static ShpProtocolResult errorWith(ShpMessage message) {
        return new ShpProtocolResult(Optional.of(message), State.ERROR);
    }

    public static ShpProtocolResult ongoing(ShpMessage message) {
        return new ShpProtocolResult(Optional.of(message), State.ONGOING);
    }

    public static ShpProtocolResult waiting(ShpMessage message) {
        return new ShpProtocolResult(Optional.of(message), State.WAITING);
    }

    public static ShpProtocolResult finished() {
        return new ShpProtocolResult(Optional.empty(), State.FINISHED);
    }

    public static ShpProtocolResult finished(ShpMessage message) {
        return new ShpProtocolResult(Optional.of(message), State.FINISHED);
    }
    
}
