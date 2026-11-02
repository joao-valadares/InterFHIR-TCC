import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class FhirMetadataHealthcheck {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.exit(2);
        }

        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
        HttpRequest request = HttpRequest.newBuilder(URI.create(args[0]))
            .timeout(Duration.ofSeconds(8))
            .header("Accept", "application/fhir+json")
            .GET()
            .build();
        HttpResponse<Void> response = client.send(
            request,
            HttpResponse.BodyHandlers.discarding()
        );
        int status = response.statusCode();
        if (status < 200 || status >= 300) {
            System.exit(1);
        }
    }
}
