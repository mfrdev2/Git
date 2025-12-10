```
minio:
  url: https://xxx.com
  serviceName: s3
  bucketName: xxx-xxx

  credential:
    tokenUrl: https://xxxxx.com/protocol/openid-connect/token
    clientId: xxxxx
    username: xxxxxx
    password: _********

```

```
        <dependency>
            <groupId>io.minio</groupId>
            <artifactId>minio</artifactId>
            <version>8.6.0</version>
        </dependency>

        <dependency>
            <groupId>com.squareup.okhttp3</groupId>
            <artifactId>okhttp</artifactId>
            <version>4.12.0</version>
        </dependency>

        <dependency>
            <groupId>com.squareup.okio</groupId>
            <artifactId>okio</artifactId>
            <version>3.9.0</version>
        </dependency>

```

```

@Slf4j
@Component
public class MinIOConfig {
    private final MinioConfigProperties properties;

    public MinIOConfig(MinioConfigProperties properties) {
        this.properties = properties;
    }

    @Bean
    public STSCredentialsProvider stsCredentialsProvider() {
        String stsEndpoint = properties.getUrl();
        String tokenUrl = properties.getCredential().getTokenUrl();
        String clientId = properties.getCredential().getClientId();
        String username = properties.getCredential().getUsername();
        String password = properties.getCredential().getPassword();
        return new STSCredentialsProvider(stsEndpoint, tokenUrl,
                clientId, username, password);
    }

    @Bean
    public MinioClient minioClient(STSCredentialsProvider credentialsProvider) {
        // MinIO client with dynamic credentials
        return MinioClient.builder()
                .endpoint(properties.getUrl())
                .credentialsProvider(credentialsProvider)
                .region("us-east-1")
                .build();
    }
}

```
```
package com.dashboard.commons.config;

import io.minio.credentials.Credentials;
import io.minio.credentials.Provider;
import okhttp3.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Custom credentials provider that uses Keycloak + STS AssumeRoleWithWebIdentity
 */
public class STSCredentialsProvider implements Provider {

    private final String stsEndpoint;
    private final String keycloakTokenUrl;
    private final String clientId;
    private final String username;
    private final String password;

    private Credentials cachedCredentials;
    private ZonedDateTime credentialsExpiry;

    private final OkHttpClient httpClient;

    public STSCredentialsProvider(String stsEndpoint, String keycloakTokenUrl,
                                  String clientId, String username, String password) {
        this.stsEndpoint = stsEndpoint;
        this.keycloakTokenUrl = keycloakTokenUrl;
        this.clientId = clientId;
        this.username = username;
        this.password = password;
        this.httpClient = new OkHttpClient();
    }

    @Override
    public synchronized Credentials fetch() {
        // Return cached credentials if still valid (with 5 minute buffer)
        if (cachedCredentials != null && credentialsExpiry != null) {
            if (ZonedDateTime.now().plusMinutes(5).isBefore(credentialsExpiry)) {
                return cachedCredentials;
            }
        }

        try {
            // Step 1: Get Keycloak token
            String keycloakToken = getKeycloakToken();

            // Step 2: Exchange for STS credentials
            STSResponse stsResponse = assumeRoleWithWebIdentity(keycloakToken);

            // Step 3: Cache and return credentials
            cachedCredentials = new Credentials(
                    stsResponse.accessKeyId,
                    stsResponse.secretAccessKey,
                    stsResponse.sessionToken,
                    null
            );
            credentialsExpiry = stsResponse.expiration;

            return cachedCredentials;

        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch credentials", e);
        }
    }

    /**
     * Get Keycloak access token
     */
    private String getKeycloakToken() throws Exception {
        RequestBody formBody = new FormBody.Builder()
                .add("grant_type", "password")
                .add("client_id", clientId)
                .add("username", username)
                .add("password", password)
                .build();

        Request request = new Request.Builder()
                .url(keycloakTokenUrl)
                .post(formBody)
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new RuntimeException("Failed to get Keycloak token: " + response);
            }

            String responseBody = response.body().string();
            return extractJsonValue(responseBody, "access_token");
        }
    }

    /**
     * Call STS AssumeRoleWithWebIdentity
     */
    private STSResponse assumeRoleWithWebIdentity(String webIdentityToken) throws Exception {
        // Build STS URL with query parameters
        HttpUrl url = HttpUrl.parse(stsEndpoint).newBuilder()
                .addQueryParameter("Version", "2011-06-15")
                .addQueryParameter("Action", "AssumeRoleWithWebIdentity")
                .addQueryParameter("WebIdentityToken", webIdentityToken)
                .build();

        Request request = new Request.Builder()
                .url(url)
                .post(RequestBody.create(new byte[0]))
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new RuntimeException("STS AssumeRoleWithWebIdentity failed: " + response);
            }

            String xmlResponse = response.body().string();
            return parseSTSResponse(xmlResponse);
        }
    }

    /**
     * Parse STS XML response
     */
    private STSResponse parseSTSResponse(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));

        Element credentials = (Element) doc.getElementsByTagName("Credentials").item(0);

        String accessKeyId = getElementText(credentials, "AccessKeyId");
        String secretAccessKey = getElementText(credentials, "SecretAccessKey");
        String sessionToken = getElementText(credentials, "SessionToken");
        String expirationStr = getElementText(credentials, "Expiration");

        ZonedDateTime expiration = ZonedDateTime.parse(expirationStr,
                DateTimeFormatter.ISO_DATE_TIME);

        return new STSResponse(accessKeyId, secretAccessKey, sessionToken, expiration);
    }

    private String getElementText(Element parent, String tagName) {
        return parent.getElementsByTagName(tagName).item(0).getTextContent();
    }

    private String extractJsonValue(String json, String key) {
        String searchKey = "\"" + key + "\"";
        int startIndex = json.indexOf(searchKey);
        if (startIndex == -1) return null;

        startIndex = json.indexOf(":", startIndex) + 1;
        int endIndex = json.indexOf(",", startIndex);
        if (endIndex == -1) {
            endIndex = json.indexOf("}", startIndex);
        }

        String value = json.substring(startIndex, endIndex).trim();
        return value.replaceAll("\"", "");
    }

    /**
         * STS Response holder
         */
        private record STSResponse(String accessKeyId, String secretAccessKey, String sessionToken,
                                   ZonedDateTime expiration) {
    }
}


```

```
package com.dashboard.commons.attachment;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

@Slf4j
@Profile("local")
@Service
public class FileStorageDevService implements FileStorageService {

    private final String uploadDir;

    public FileStorageDevService(@Value("${file-upload-dir}") String uploadDir) {
        this.uploadDir = uploadDir;
    }

    /**
     * Initializes the upload directory on service startup
     * Creates the base directory if it doesn't exist
     */
    @PostConstruct
    public void init() {
        try {
            Path uploadPath = Paths.get(uploadDir);
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
                log.info("Upload directory created successfully - path: [{}]", uploadDir);
            } else {
                log.info("Upload directory already exists - path: [{}]", uploadDir);
            }
        } catch (IOException ex) {
            log.error("Failed to create upload directory - path: [{}], error: [{}]", uploadDir, ex.getMessage(), ex);
            throw new AttachmentException("Failed to initialize upload directory: " + ex.getMessage(), ex);
        }
    }

    /**
     * Stores a file in the local file system
     *
     * @param fileServerOrigin the origin identifier for the file server
     * @param folderName       the folder name where the file will be stored
     * @param fileKey          the unique file key/name
     * @param fileByteArray    the file content as byte array
     * @return FileStoreResponse containing the file path
     * @throws AttachmentException if file upload fails
     */
    @Override
    public FileStoreResponse storeFile(String fileServerOrigin, String folderName, String fileKey, byte[] fileByteArray) {
        String objectKey = buildObjectKey(fileServerOrigin, folderName, fileKey);
        Path filePath = Paths.get(uploadDir, fileServerOrigin, folderName);
        Path fullFilePath = filePath.resolve(fileKey);

        log.debug("Attempting to upload file locally - objectKey: [{}], size: [{}] bytes", objectKey, fileByteArray.length);

        try {
            // Create directories if they don't exist
            if (!Files.exists(filePath)) {
                Files.createDirectories(filePath);
                log.debug("Created directory structure - path: [{}]", filePath);
            }

            // Write file to disk
            Files.write(fullFilePath, fileByteArray,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING);

            String fileUrl = buildFileUrl(objectKey);
            log.info("File uploaded successfully to local storage - objectKey: [{}], path: [{}], size: [{}] bytes",
                    objectKey, fullFilePath.toAbsolutePath(), fileByteArray.length);

            return new FileStoreResponse(fileUrl);

        } catch (IOException ex) {
            log.error("Failed to upload file to local storage - objectKey: [{}], path: [{}], error: [{}]",
                    objectKey, fullFilePath.toAbsolutePath(), ex.getMessage(), ex);
            throw new AttachmentException("Failed to upload file to local storage: " + ex.getMessage(), ex);
        }
    }

    /**
     * Retrieves a file from the local file system by its key
     *
     * @param fileServerOrigin the origin identifier for the file server
     * @param folderName       the folder name where the file is stored
     * @param fileKey          the unique file key/name
     * @return byte array containing the file content
     * @throws AttachmentException if file retrieval fails
     */
    @Override
    public byte[] getFileByFileKey(String fileServerOrigin, String folderName, String fileKey) {
        String objectKey = buildObjectKey(fileServerOrigin, folderName, fileKey);
        Path fullFilePath = Paths.get(uploadDir, fileServerOrigin, folderName, fileKey);

        log.debug("Attempting to fetch file from local storage - objectKey: [{}]", objectKey);

        try {
            if (!Files.exists(fullFilePath)) {
                log.warn("File not found in local storage - objectKey: [{}], path: [{}]",
                        objectKey, fullFilePath.toAbsolutePath());
                throw new AttachmentException("File not found: " + objectKey);
            }

            byte[] bytes = Files.readAllBytes(fullFilePath);
            log.info("File fetched successfully from local storage - objectKey: [{}], path: [{}], size: [{}] bytes",
                    objectKey, fullFilePath.toAbsolutePath(), bytes.length);

            return bytes;

        } catch (IOException ex) {
            log.error("Failed to fetch file from local storage - objectKey: [{}], path: [{}], error: [{}]",
                    objectKey, fullFilePath.toAbsolutePath(), ex.getMessage(), ex);
            throw new AttachmentException("Failed to fetch file from local storage: " + ex.getMessage(), ex);
        }
    }

    /**
     * Builds the complete object key from components
     */
    private String buildObjectKey(String fileServerOrigin, String folderName, String fileKey) {
        return String.join("/", fileServerOrigin, folderName, fileKey);
    }

    /**
     * Builds the file URL/path reference
     */
    private String buildFileUrl(String objectKey) {
        return uploadDir + "/" + objectKey;
    }
}


```
```

import io.minio.GetObjectArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import static org.springframework.http.MediaTypeFactory.getMediaType;

@Slf4j
@Profile("!local")
@RequiredArgsConstructor
@Service
public class FileStorageProdService implements FileStorageService {
    private final MinioConfigProperties properties;
    private final MinioClient minioClient;

    /**
     * Stores a file in MinIO with automatic content type detection
     *
     * @param fileServerOrigin the origin identifier for the file server
     * @param folderName       the folder name where the file will be stored
     * @param fileKey          the unique file key/name
     * @param fileByteArray    the file content as byte array
     * @return FileStoreResponse containing the file URL
     * @throws AttachmentException if file upload fails
     */
    @Override
    public FileStoreResponse storeFile(String fileServerOrigin, String folderName, String fileKey, byte[] fileByteArray) {
        String objectKey = buildObjectKey(fileServerOrigin, folderName, fileKey);

        log.debug("Attempting to upload file - objectKey: [{}], size: [{}] bytes", objectKey, fileByteArray.length);

        try (InputStream inputStream = new ByteArrayInputStream(fileByteArray)) {
            String contentType = getMediaType(fileKey)
                    .map(MediaType::toString)
                    .orElse("application/octet-stream");

            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(properties.getBucketName())
                            .object(objectKey)
                            .stream(inputStream, fileByteArray.length, -1)
                            .contentType(contentType)
                            .build()
            );

            String fileUrl = buildFileUrl(objectKey);
            log.info("File uploaded successfully - objectKey: [{}], url: [{}], contentType: [{}], size: [{}] bytes",
                    objectKey, fileUrl, contentType, fileByteArray.length);

            return new FileStoreResponse(fileUrl);

        } catch (Exception ex) {
            log.error("Failed to upload file to MinIO - objectKey: [{}], error: [{}]", objectKey, ex.getMessage(), ex);
            throw new AttachmentException("Failed to upload file to MinIO: " + ex.getMessage(), ex);
        }
    }

    /**
     * Retrieves a file from MinIO by its key
     *
     * @param fileServerOrigin the origin identifier for the file server
     * @param folderName       the folder name where the file is stored
     * @param fileKey          the unique file key/name
     * @return byte array containing the file content
     * @throws AttachmentException if file retrieval fails
     */
    @Override
    public byte[] getFileByFileKey(String fileServerOrigin, String folderName, String fileKey) {
        String objectKey = buildObjectKey(fileServerOrigin, folderName, fileKey);

        log.debug("Attempting to fetch file from MinIO - objectKey: [{}]", objectKey);

        try (InputStream inputStream = minioClient.getObject(
                GetObjectArgs.builder()
                        .bucket(properties.getBucketName())
                        .object(objectKey)
                        .build())) {

            byte[] bytes = inputStream.readAllBytes();
            log.info("File fetched successfully from MinIO - objectKey: [{}], size: [{}] bytes", objectKey, bytes.length);
            return bytes;

        } catch (Exception ex) {
            log.error("Failed to fetch file from MinIO - objectKey: [{}], error: [{}]", objectKey, ex.getMessage(), ex);
            throw new AttachmentException("Failed to fetch file from MinIO: " + ex.getMessage(), ex);
        }
    }

    /**
     * Builds the complete object key from components
     */
    private String buildObjectKey(String fileServerOrigin, String folderName, String fileKey) {
        return String.join("/", fileServerOrigin, folderName, fileKey);
    }

    /**
     * Builds the complete file URL
     */
    private String buildFileUrl(String objectKey) {
        return String.format("%s/%s/%s", properties.getUrl(), properties.getBucketName(), objectKey);
    }
}
```
```
public interface FileStorageService {
    FileStoreResponse storeFile(String fileServerOrigin, String folderName, String fileKey, byte[] fileByteArray);
    byte [] getFileByFileKey(String fileServerOrigin,String folderName,String fileKey);
}

```
