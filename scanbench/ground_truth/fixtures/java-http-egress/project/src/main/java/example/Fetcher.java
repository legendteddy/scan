package example;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Set;

public final class Fetcher {
    public byte[] fetch(String userUrl) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.ALWAYS)
                .build();
        HttpRequest request = HttpRequest.newBuilder(URI.create(userUrl)).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofByteArray()).body();
    }

    public byte[] fetchApproved(String userUrl) throws Exception {
        URI uri = URI.create(userUrl);
        if (!Set.of("https").contains(uri.getScheme()) || !"api.example.com".equals(uri.getHost())) {
            throw new IllegalArgumentException("destination not allowed");
        }
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(2))
                .build();
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(3))
                .GET()
                .build();
        byte[] body = client.send(request, HttpResponse.BodyHandlers.ofByteArray()).body();
        if (body.length > 1_048_576) {
            throw new IllegalStateException("response too large");
        }
        return body;
    }
}
