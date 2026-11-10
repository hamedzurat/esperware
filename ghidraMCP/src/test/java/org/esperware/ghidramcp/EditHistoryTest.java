package org.esperware.ghidramcp;

import static org.junit.jupiter.api.Assertions.*;
import com.google.gson.JsonParser;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EditHistoryTest {
    @TempDir Path directory;

    @Test void recordsEditsAndRevertsAcrossRestarts() throws Exception {
        Path file = directory.resolve("history.sqlite");
        try (EditHistory history = new EditHistory(file, "127.0.0.1", 0)) {
            history.append("project", "/file", "session", 1, 4, "edit", "e-1", "0040",
                    Map.of("kind", "function"), Map.of("kind", "comment", "value", "note"),
                    Map.of("status", "complete", "code", "before"), Map.of("status", "complete", "code", "after"));
            history.append("project", "/file", "session", 1, 5, "revert", "e-1", "0040", null, null,
                    Map.of("status", "complete", "code", "after"), Map.of("status", "timed_out", "error", "timeout"));
            var list = request(history.port(), "/api/v1/edits?program=%2Ffile&limit=1");
            assertEquals(200, list.statusCode());
            var body = JsonParser.parseString(list.body()).getAsJsonObject();
            assertEquals("after", body.getAsJsonArray("edits").get(0).getAsJsonObject().get("after_code").getAsString());
            assertEquals(1, body.get("next_after").getAsInt());
            assertEquals(400, request(history.port(), "/api/v1/edits?limit=101").statusCode());
            assertEquals(404, request(history.port(), "/api/v1/edits/99").statusCode());
        }
        try (EditHistory reopened = new EditHistory(file, "127.0.0.1", 0)) {
            var row = JsonParser.parseString(request(reopened.port(), "/api/v1/edits/2").body()).getAsJsonObject();
            assertEquals("revert", row.get("operation").getAsString());
            assertEquals("timed_out", row.get("after_status").getAsString());
            assertEquals("timeout", row.get("after_error").getAsString());
            assertEquals(1, JsonParser.parseString(request(reopened.port(), "/api/v1/edits?after=1").body()).getAsJsonObject().getAsJsonArray("edits").size());
        }
    }

    private static HttpResponse<String> request(int port, String path) throws Exception {
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }
}
