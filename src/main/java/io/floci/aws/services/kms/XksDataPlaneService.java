package io.floci.aws.services.kms;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.floci.aws.core.common.AwsException;
import io.floci.aws.core.common.RequestContext;
import io.floci.aws.services.iam.RequestCallerResolver;
import io.floci.aws.services.kms.model.KmsCustomKeyStore;
import io.floci.aws.services.kms.model.KmsKey;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;
import java.util.regex.Pattern;

/** XKS v1 key association and cryptographic data-plane operations for PUBLIC_ENDPOINT stores. */
@ApplicationScoped
public class XksDataPlaneService {
    private static final byte[] MAGIC = {0x4B, 0x4D, 0x53, 0x58}; // KMSX
    private static final byte VERSION = 1;
    private static final int MAX_METADATA_BYTES = 20;
    private static final int MAX_AAD_BYTES = 8192;
    private static final Pattern EXTERNAL_KEY_ID = Pattern.compile("[A-Za-z0-9._-]{1,128}");

    private final KmsCustomKeyStoreRegistry registry;
    private final XksProxyClient proxyClient;
    private final ObjectMapper objectMapper;
    private final RequestCallerResolver callerResolver;
    private final RequestContext requestContext;

    @Inject
    public XksDataPlaneService(KmsCustomKeyStoreRegistry registry, XksProxyClient proxyClient,
                               ObjectMapper objectMapper, RequestCallerResolver callerResolver,
                               RequestContext requestContext) {
        this.registry = registry;
        this.proxyClient = proxyClient;
        this.objectMapper = objectMapper;
        this.callerResolver = callerResolver;
        this.requestContext = requestContext;
    }

    /** Validates the external key with the proxy before a KMS key association is persisted. */
    public void validateKeyAssociation(String customKeyStoreId, String xksKeyId, String region) {
        requireExternalKeyId(xksKeyId);
        KmsCustomKeyStore store = requireConnectedStore(customKeyStoreId, region);
        ObjectNode payload = objectMapper.createObjectNode();
        payload.set("requestMetadata", requestMetadata("CreateKey", null));
        JsonNode metadata = proxyClient.post(URI.create(store.getProxyUriEndpoint()), store.getProxyUriPath(),
                store.getAccessKeyId(), registry.secretAccessKey(customKeyStoreId, region), region,
                "/keys/" + xksKeyId + "/metadata", payload);
        if (!"AES_256".equals(metadata.path("keySpec").asText(null))) {
            throw new AwsException("XksKeyInvalidConfigurationException",
                    "The external key must be a 256-bit AES key", 400);
        }
        JsonNode usage = metadata.path("keyUsage");
        if (!usage.isArray() || usage.size() > 10 || !contains(usage, "ENCRYPT") || !contains(usage, "DECRYPT")) {
            throw new AwsException("XksKeyInvalidConfigurationException",
                    "The external key must support both encryption and decryption", 400);
        }
        if (!"ENABLED".equals(metadata.path("keyStatus").asText(null))) {
            throw new AwsException("XksKeyInvalidConfigurationException",
                    "The external key must be enabled in the external key manager", 400);
        }
    }

    public byte[] encrypt(KmsKey key, byte[] plaintext, Map<String, String> encryptionContext, String operation) {
        KmsCustomKeyStore store = requireConnectedStore(key.getCustomKeyStoreId(), keyRegion(key));
        if (plaintext == null || plaintext.length > 4300) {
            throw new AwsException("ValidationException", "XKS plaintext exceeds the 4300-byte proxy limit", 400);
        }
        byte[] aad = additionalAuthenticatedData(key, encryptionContext);
        if (aad.length > MAX_AAD_BYTES) {
            throw new AwsException("ValidationException", "EncryptionContext exceeds the XKS AAD limit", 400);
        }
        ObjectNode payload = objectMapper.createObjectNode();
        payload.set("requestMetadata", requestMetadata(operation, key.getArn()));
        payload.put("additionalAuthenticatedData", Base64.getEncoder().encodeToString(aad));
        payload.put("plaintext", Base64.getEncoder().encodeToString(plaintext));
        payload.put("encryptionAlgorithm", "AES_GCM");
        payload.put("ciphertextDataIntegrityValueAlgorithm", "SHA_256");
        JsonNode response = proxyClient.post(URI.create(store.getProxyUriEndpoint()), store.getProxyUriPath(),
                store.getAccessKeyId(), registry.secretAccessKey(key.getCustomKeyStoreId(), keyRegion(key)),
                keyRegion(key), "/keys/" + key.getXksKeyId() + "/encrypt", payload);

        byte[] ciphertext = decodeRequired(response, "ciphertext");
        byte[] iv = decodeRequired(response, "initializationVector");
        byte[] tag = decodeRequired(response, "authenticationTag");
        byte[] metadata = decodeOptional(response, "ciphertextMetadata");
        byte[] cdiv = decodeRequired(response, "ciphertextDataIntegrityValue");
        if (ciphertext.length != plaintext.length || (iv.length != 12 && iv.length != 16)
                || tag.length != 16 || metadata.length > MAX_METADATA_BYTES || cdiv.length != 32
                || !MessageDigest.isEqual(cdiv, cdiv(aad, metadata, iv, ciphertext, tag))) {
            throw new AwsException("XksProxyInvalidResponseException",
                    "The XKS proxy returned an invalid or corrupted encryption response", 400);
        }
        return encodeBlob(key, metadata, iv, ciphertext, tag);
    }

    public byte[] decrypt(KmsKey key, byte[] blob, Map<String, String> encryptionContext, String operation) {
        Blob parsed = parseBlob(blob);
        if (!Objects.equals(key.getKeyId(), parsed.keyId())
                || !Objects.equals(key.getCustomKeyStoreId(), parsed.customKeyStoreId())
                || !Objects.equals(key.getXksKeyId(), parsed.xksKeyId())) {
            throw new AwsException("InvalidCiphertextException", null, 400);
        }
        KmsCustomKeyStore store = requireConnectedStore(key.getCustomKeyStoreId(), keyRegion(key));
        byte[] aad = additionalAuthenticatedData(key, encryptionContext);
        if (aad.length > MAX_AAD_BYTES) {
            throw new AwsException("ValidationException", "EncryptionContext exceeds the XKS AAD limit", 400);
        }
        ObjectNode payload = objectMapper.createObjectNode();
        payload.set("requestMetadata", requestMetadata(operation, key.getArn()));
        payload.put("additionalAuthenticatedData", Base64.getEncoder().encodeToString(aad));
        payload.put("ciphertext", Base64.getEncoder().encodeToString(parsed.ciphertext()));
        if (parsed.metadata().length > 0) {
            payload.put("ciphertextMetadata", Base64.getEncoder().encodeToString(parsed.metadata()));
        }
        payload.put("encryptionAlgorithm", "AES_GCM");
        payload.put("initializationVector", Base64.getEncoder().encodeToString(parsed.iv()));
        payload.put("authenticationTag", Base64.getEncoder().encodeToString(parsed.tag()));
        JsonNode response = proxyClient.post(URI.create(store.getProxyUriEndpoint()), store.getProxyUriPath(),
                store.getAccessKeyId(), registry.secretAccessKey(key.getCustomKeyStoreId(), keyRegion(key)),
                keyRegion(key), "/keys/" + key.getXksKeyId() + "/decrypt", payload);
        byte[] plaintext = decodeRequired(response, "plaintext");
        if (plaintext.length != parsed.ciphertext().length) {
            Arrays.fill(plaintext, (byte) 0);
            throw new AwsException("XksProxyInvalidResponseException",
                    "The XKS proxy returned plaintext with an invalid length", 400);
        }
        return plaintext;
    }

    public static boolean isXksCiphertextBlob(byte[] blob) {
        if (blob == null || blob.length < MAGIC.length) return false;
        for (int i = 0; i < MAGIC.length; i++) if (blob[i] != MAGIC[i]) return false;
        return true;
    }

    public static String keyIdFromBlob(byte[] blob) {
        return parseBlob(blob).keyId();
    }

    private ObjectNode requestMetadata(String operation, String keyArn) {
        ObjectNode metadata = objectMapper.createObjectNode();
        metadata.put("awsPrincipalArn", callerResolver.caller().principalArn());
        if (keyArn != null) metadata.put("kmsKeyArn", keyArn);
        metadata.put("kmsOperation", operation);
        String requestId = requestContext.getRequestId();
        metadata.put("kmsRequestId", requestId == null || requestId.isBlank()
                ? UUID.randomUUID().toString() : requestId);
        return metadata;
    }

    private KmsCustomKeyStore requireConnectedStore(String id, String region) {
        if (id == null || id.isBlank()) {
            throw new AwsException("CustomKeyStoreInvalidStateException", "The KMS key has no external custom key store", 400);
        }
        KmsCustomKeyStore store = registry.require(id, region);
        if (!KmsCustomKeyStore.STATE_CONNECTED.equals(store.getConnectionState())) {
            throw new AwsException("CustomKeyStoreInvalidStateException",
                    "The external custom key store is not connected to its XKS proxy", 400);
        }
        return store;
    }

    private static boolean contains(JsonNode values, String expected) {
        for (JsonNode value : values) if (expected.equals(value.asText())) return true;
        return false;
    }

    private byte[] additionalAuthenticatedData(KmsKey key, Map<String, String> context) {
        ObjectNode aad = objectMapper.createObjectNode();
        aad.put("kmsKeyArn", key.getArn());
        aad.put("customKeyStoreId", key.getCustomKeyStoreId());
        aad.put("xksKeyId", key.getXksKeyId());
        ObjectNode values = aad.putObject("encryptionContext");
        new TreeMap<>(context == null ? Map.of() : context).forEach(values::put);
        try {
            return objectMapper.writeValueAsBytes(aad);
        } catch (IOException e) {
            throw new AwsException("InternalFailure", "Could not encode XKS authenticated data", 500);
        }
    }

    private static byte[] cdiv(byte[] aad, byte[] metadata, byte[] iv, byte[] ciphertext, byte[] tag) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(aad);
            digest.update(metadata);
            digest.update(iv);
            digest.update(ciphertext);
            digest.update(tag);
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new AwsException("InternalFailure", "SHA-256 is unavailable", 500);
        }
    }

    private static byte[] encodeBlob(KmsKey key, byte[] metadata, byte[] iv, byte[] ciphertext, byte[] tag) {
        byte[] keyId = key.getKeyId().getBytes(StandardCharsets.UTF_8);
        byte[] storeId = key.getCustomKeyStoreId().getBytes(StandardCharsets.UTF_8);
        byte[] xksId = key.getXksKeyId().getBytes(StandardCharsets.UTF_8);
        if (keyId.length > 256 || storeId.length > 256 || xksId.length > 128
                || ciphertext.length > 4300) {
            throw new AwsException("InternalFailure", "XKS ciphertext envelope exceeds the permitted size", 500);
        }
        ByteBuffer out = ByteBuffer.allocate(MAGIC.length + 1 + 2 + keyId.length + 2 + storeId.length
                + 2 + xksId.length + 1 + metadata.length + 1 + iv.length + 4 + ciphertext.length + 1 + tag.length);
        out.put(MAGIC).put(VERSION);
        out.putShort((short) keyId.length).put(keyId);
        out.putShort((short) storeId.length).put(storeId);
        out.putShort((short) xksId.length).put(xksId);
        out.put((byte) metadata.length).put(metadata);
        out.put((byte) iv.length).put(iv);
        out.putInt(ciphertext.length).put(ciphertext);
        out.put((byte) tag.length).put(tag);
        return out.array();
    }

    private static Blob parseBlob(byte[] bytes) {
        try {
            if (!isXksCiphertextBlob(bytes) || bytes.length > KmsService.MAX_CIPHERTEXT_BYTES) throw new IllegalArgumentException();
            ByteBuffer in = ByteBuffer.wrap(bytes);
            byte[] magic = new byte[MAGIC.length]; in.get(magic);
            if (in.get() != VERSION) throw new IllegalArgumentException();
            String keyId = readString(in, 256);
            String storeId = readString(in, 256);
            String xksId = readString(in, 128);
            int metadataLength = in.get() & 0xff;
            if (metadataLength > MAX_METADATA_BYTES || metadataLength > in.remaining()) throw new IllegalArgumentException();
            byte[] metadata = new byte[metadataLength]; in.get(metadata);
            int ivLength = in.get() & 0xff;
            if ((ivLength != 12 && ivLength != 16) || ivLength > in.remaining()) throw new IllegalArgumentException();
            byte[] iv = new byte[ivLength]; in.get(iv);
            int ciphertextLength = in.getInt();
            if (ciphertextLength < 1 || ciphertextLength > 4300
                    || ciphertextLength > in.remaining() - 1) throw new IllegalArgumentException();
            byte[] ciphertext = new byte[ciphertextLength]; in.get(ciphertext);
            int tagLength = in.get() & 0xff;
            if (tagLength != 16 || in.remaining() != tagLength) throw new IllegalArgumentException();
            byte[] tag = new byte[tagLength]; in.get(tag);
            return new Blob(keyId, storeId, xksId, metadata, iv, ciphertext, tag);
        } catch (RuntimeException e) {
            throw new AwsException("InvalidCiphertextException", null, 400);
        }
    }

    private static String readString(ByteBuffer in, int maximum) {
        int length = in.getShort() & 0xffff;
        if (length < 1 || length > maximum || length > in.remaining()) throw new IllegalArgumentException();
        byte[] bytes = new byte[length]; in.get(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static byte[] decodeRequired(JsonNode node, String field) {
        if (!node.path(field).isTextual()) {
            throw new AwsException("XksProxyInvalidResponseException", "The XKS proxy response is missing a required field", 400);
        }
        try {
            return Base64.getDecoder().decode(node.path(field).asText());
        } catch (IllegalArgumentException e) {
            throw new AwsException("XksProxyInvalidResponseException", "The XKS proxy response contains invalid Base64", 400);
        }
    }

    private static byte[] decodeOptional(JsonNode node, String field) {
        if (node.path(field).isMissingNode() || node.path(field).isNull()) return new byte[0];
        return decodeRequired(node, field);
    }

    private static void requireExternalKeyId(String value) {
        if (value == null || ".".equals(value) || "..".equals(value) || !EXTERNAL_KEY_ID.matcher(value).matches()) {
            throw new AwsException("ValidationException", "XksKeyId must contain 1 to 128 valid characters", 400);
        }
    }

    private static String keyRegion(KmsKey key) {
        if (key.getArn() == null) throw new AwsException("InternalFailure", "KMS key ARN is missing", 500);
        String[] parts = key.getArn().split(":", 6);
        if (parts.length < 6 || parts[3].isBlank()) throw new AwsException("InternalFailure", "KMS key Region is missing", 500);
        return parts[3];
    }

    private record Blob(String keyId, String customKeyStoreId, String xksKeyId,
                        byte[] metadata, byte[] iv, byte[] ciphertext, byte[] tag) { }
}
