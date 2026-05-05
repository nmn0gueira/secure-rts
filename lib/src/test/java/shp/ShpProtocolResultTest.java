package shp;

import shp.protocol.ShpProtocolResult;
import shp.protocol.State;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ShpProtocolResultTest {

    private static ShpMessage dummyMessage() {
        return new ShpMessage(new byte[]{0x01}, List.of(new byte[]{0x02}));
    }

    @Test
    void errorHasNoResponseAndErrorState() {
        var result = ShpProtocolResult.error();
        assertEquals(State.ERROR, result.state());
        assertTrue(result.response().isEmpty());
    }

    @Test
    void ongoingCarriesMessageAndOngoingState() {
        ShpMessage msg = dummyMessage();
        var result = ShpProtocolResult.ongoing(msg);
        assertEquals(State.ONGOING, result.state());
        assertTrue(result.response().isPresent());
        assertSame(msg, result.response().get());
    }

    @Test
    void waitingCarriesMessageAndWaitingState() {
        ShpMessage msg = dummyMessage();
        var result = ShpProtocolResult.waiting(msg);
        assertEquals(State.WAITING, result.state());
        assertTrue(result.response().isPresent());
        assertSame(msg, result.response().get());
    }

    @Test
    void finishedHasNoResponseAndFinishedState() {
        var result = ShpProtocolResult.finished();
        assertEquals(State.FINISHED, result.state());
        assertTrue(result.response().isEmpty());
    }
}
