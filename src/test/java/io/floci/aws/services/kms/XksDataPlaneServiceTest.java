package io.floci.aws.services.kms;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpsServer;
import io.floci.aws.config.FlociCertificateAuthority;
import io.floci.aws.core.common.AwsException;
import io.floci.aws.core.common.RegionResolver;
import io.floci.aws.core.common.RequestContext;
import io.floci.aws.core.storage.AccountAwareStorageBackend;
import io.floci.aws.core.storage.InMemoryStorage;
import io.floci.aws.services.iam.IamService;
import io.floci.aws.services.iam.RequestCallerResolver;
import io.floci.aws.services.kms.model.KmsCustomKeyStore;
import io.floci.aws.services.kms.model.KmsKey;
import io.floci.aws.testing.LocalHttpsServer;
import io.floci.aws.testing.TlsTrust;
import org.apache.hc.client5.http.DnsResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class XksDataPlaneServiceTest {
    private static final String ACCOUNT = "000000000000";
    private static final String REGION = "us-east-1";
    private static final String ACCESS_KEY = "ABCDEFGHIJKLMNOPQRST";
    private static final String SECRET_KEY = "A".repeat(43);
    private static final byte[] EXTERNAL_AES_KEY = new byte[32];

    private static DnsResolver loopbackResolver() {
        return new DnsResolver() {
            @Override
            public InetAddress[] resolve(String host) throws UnknownHostException {
                return new InetAddress[]{InetAddress.getByName("127.0.0.1")};
            }
            @Override
            public String resolveCanonicalHostname(String host) { return host; }
        };
    }

    @Test
    void createsXksKeyAndRoutesDoubleEncryptedRoundTripThroughProxy(@TempDir Path tlsDirectory) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        FlociCertificateAuthority ca = FlociCertificateAuthority.loadOrCreate(tlsDirectory);
        HttpsServer server = LocalHttpsServer.issuedBy(ca);
        AtomicReference<String> lastRequestId = new AtomicReference<>();
        AtomicReference<String> lastOperation = new AtomicReference<>();
        server.createContext("/kms/xks/v1/keys/external-key-01/metadata", exchange -> {
            JsonNode request = mapper.readTree(exchange.getRequestBody());
            lastRequestId.set(request.path("requestMetadata").path("kmsRequestId").asText());
            lastOperation.set(request.path("requestMetadata").path("kmsOperation").asText());
            assertEquals("arn:aws:iam::000000000000:user/xks-test",
                    request.path("requestMetadata").path("awsPrincipalArn").asText());
            respond(exchange, """
                    {"keySpec":"AES_256","keyUsage":["ENCRYPT","DECRYPT"],"keyStatus":"ENABLED"}
                    """);
        });
        server.createContext("/kms/xks/v1/keys/external-key-01/encrypt", exchange -> {
            JsonNode request = mapper.readTree(exchange.getRequestBody());
            JsonNode metadata = request.path("requestMetadata");
            lastRequestId.set(metadata.path("kmsRequestId").asText());
            lastOperation.set(metadata.path("kmsOperation").asText());
            byte[] aad = Base64.getDecoder().decode(request.path("additionalAuthenticatedData").asText());
            byte[] plaintext = Base64.getDecoder().decode(request.path("plaintext").asText());
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            byte[] combined;
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(EXTERNAL_AES_KEY, "AES"), new GCMParameterSpec(128, iv));
                cipher.updateAAD(aad);
                combined = cipher.doFinal(plaintext);
            } catch (java.security.GeneralSecurityException e) {
                throw new java.io.IOException(e);
            }
            byte[] ciphertext = Arrays.copyOf(combined, combined.length - 16);
            byte[] tag = Arrays.copyOfRange(combined, combined.length - 16, combined.length);
            byte[] cdiv = sha256(aad, new byte[0], iv, ciphertext, tag);
            ObjectNode response = mapper.createObjectNode();
            response.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
            response.put("initializationVector", Base64.getEncoder().encodeToString(iv));
            response.put("authenticationTag", Base64.getEncoder().encodeToString(tag));
            response.put("ciphertextDataIntegrityValue", Base64.getEncoder().encodeToString(cdiv));
            respond(exchange, mapper.writeValueAsString(response));
        });
        server.createContext("/kms/xks/v1/keys/external-key-01/decrypt", exchange -> {
            JsonNode request = mapper.readTree(exchange.getRequestBody());
            JsonNode metadata = request.path("requestMetadata");
            lastRequestId.set(metadata.path("kmsRequestId").asText());
            lastOperation.set(metadata.path("kmsOperation").asText());
            byte[] aad = Base64.getDecoder().decode(request.path("additionalAuthenticatedData").asText());
            byte[] ciphertext = Base64.getDecoder().decode(request.path("ciphertext").asText());
            byte[] iv = Base64.getDecoder().decode(request.path("initializationVector").asText());
            byte[] tag = Base64.getDecoder().decode(request.path("authenticationTag").asText());
            byte[] combined = ByteBuffer.allocate(ciphertext.length + tag.length).put(ciphertext).put(tag).array();
            byte[] plaintext;
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(EXTERNAL_AES_KEY, "AES"), new GCMParameterSpec(128, iv));
                cipher.updateAAD(aad);
                plaintext = cipher.doFinal(combined);
            } catch (javax.crypto.AEADBadTagException e) {
                respond(exchange, 400, "{\"errorName\":\"InvalidCiphertextException\"}");
                return;
            } catch (java.security.GeneralSecurityException e) {
                throw new java.io.IOException(e);
            }
            ObjectNode response = mapper.createObjectNode();
            response.put("plaintext", Base64.getEncoder().encodeToString(plaintext));
            respond(exchange, mapper.writeValueAsString(response));
            Arrays.fill(plaintext, (byte) 0);
        });
        server.start();

        String endpoint = "https://localhost:" + server.getAddress().getPort();
        KmsCustomKeyStoreRegistry registry = new KmsCustomKeyStoreRegistry(
                AccountAwareStorageBackend.inMemory(ACCOUNT), new RegionResolver(REGION, ACCOUNT),
                new XksCredentialCipher(Base64.getEncoder().encodeToString(new byte[32])));
        KmsCustomKeyStore candidate = new KmsCustomKeyStore();
        candidate.setCustomKeyStoreName("test-xks");
        candidate.setAccessKeyId(ACCESS_KEY);
        candidate.setProxyUriEndpoint(endpoint);
        candidate.setProxyUriPath("/kms/xks/v1");
        String storeId = registry.create(candidate, SECRET_KEY, REGION).getCustomKeyStoreId();
        registry.beginConnect(storeId, REGION);
        registry.markConnected(storeId, REGION);

        RequestCallerResolver callerResolver = mock(RequestCallerResolver.class);
        String principalArn = "arn:aws:iam::" + ACCOUNT + ":user/xks-test";
        when(callerResolver.caller()).thenReturn(new IamService.CallerArns(
                principalArn, principalArn, "User", null, null, false, Map.of(), null));
        RequestContext requestContext = new RequestContext();
        requestContext.setRequestId("12345678-1234-4234-8234-123456789012");
        try (XksProxyClient proxy = new XksProxyClient(mapper, loopbackResolver(), TlsTrust.trusting(ca.certificate()), true)) {
            XksDataPlaneService dataPlane = new XksDataPlaneService(registry, proxy, mapper, callerResolver, requestContext);
            KmsService kms = new KmsService(new InMemoryStorage<>(), new InMemoryStorage<>(), new InMemoryStorage<>(),
                    new RegionResolver(REGION, ACCOUNT), new SecureRandom(), dataPlane);
            KmsKey key = kms.createKey("external key", "ENCRYPT_DECRYPT", "SYMMETRIC_DEFAULT", null, Map.of(),
                    "EXTERNAL_KEY_STORE", false, storeId, "external-key-01", REGION);
            byte[] plaintext = "NEXUS-Q XKS data-plane round trip".getBytes(StandardCharsets.UTF_8);
            Map<String, String> context = Map.of("purpose", "integration-test", "tenant", "nexus-q");

            KmsService.EncryptResult encrypted = kms.encrypt(key.getKeyId(), plaintext, context, null, REGION);
            assertTrue(XksDataPlaneService.isXksCiphertextBlob(encrypted.ciphertext()));
            assertEquals("Encrypt", lastOperation.get());
            assertEquals(requestContext.getRequestId(), lastRequestId.get());

            KmsService.DecryptResult decrypted = kms.decryptAndResolveKey(
                    encrypted.ciphertext(), context, REGION, key.getKeyId(), null);
            assertArrayEquals(plaintext, decrypted.plaintext());
            assertEquals(key.getArn(), decrypted.keyArn());
            assertEquals("Decrypt", lastOperation.get());
            AwsException wrongContext = assertThrows(AwsException.class, () -> kms.decryptAndResolveKey(
                    encrypted.ciphertext(), Map.of("purpose", "wrong"), REGION, key.getKeyId(), null));
            assertEquals("KMSInvalidStateException", wrongContext.getErrorCode());
        } finally {
            server.stop(0);
        }
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, String body) throws java.io.IOException {
        respond(exchange, 200, body);
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String body)
            throws java.io.IOException {
        byte[] response = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
    }

    private static byte[] sha256(byte[]... parts) throws java.io.IOException {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) digest.update(part);
            return digest.digest();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new java.io.IOException(e);
        }
    }
}
