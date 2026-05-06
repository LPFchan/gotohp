package backend

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"app/generated"

	"google.golang.org/protobuf/proto"
)

type Api struct {
	androidAPIVersion   int64
	model               string
	make                string
	clientVersionCode   int64
	userAgent           string
	language            string
	authData            string
	client              *http.Client
	authResponseCache   map[string]string
	bearerTokenOverride string
	authTimeMillis      int64
}

type AuthResponse struct {
	Expiry string
	Auth   string
}

func NewApi() (*Api, error) {
	selectedEmail := AppConfig.Selected
	if len(selectedEmail) == 0 {
		return nil, fmt.Errorf("no account is selected")
	}
	credentials := ""
	language := ""
	for _, c := range AppConfig.Credentials {
		params, err := url.ParseQuery(c)
		if err != nil {
			continue
		}
		if params.Get("Email") == selectedEmail {
			credentials = c
			language = params.Get("lang")
		}
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("no credentials with matching selected email found")
	}

	client, err := NewHTTPClientWithProxy(AppConfig.Proxy)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	api := &Api{
		androidAPIVersion: 33,
		model:             "WayDroid x86_64 Device",
		make:              "Waydroid",
		clientVersionCode: 51650172,
		language:          language,
		authData:          strings.TrimSpace(credentials),
		client:            client,
		authTimeMillis:    time.Now().UnixMilli(),
		authResponseCache: map[string]string{
			"Expiry": "0",
			"Auth":   "",
		},
	}

	api.userAgent = fmt.Sprintf(
		"com.google.android.apps.photos/%d (Linux; U; Android 13; %s; %s; Build/TQ3A.230901.001; Cronet/147.0.7727.49) (gzip)",
		api.clientVersionCode,
		strings.ReplaceAll(api.language, "-", "_"),
		api.model,
	)

	if token := os.Getenv("GOTOHP_BEARER_TOKEN"); token != "" {
		api.bearerTokenOverride = strings.TrimSpace(token)
	}

	return api, nil
}

func (a *Api) BearerToken() (string, error) {
	if a.bearerTokenOverride != "" {
		return a.bearerTokenOverride, nil
	}

	expiryStr := a.authResponseCache["Expiry"]
	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid expiry time: %w", err)
	}

	if expiry <= time.Now().Unix() {
		resp, err := a.getAuthToken()
		if err != nil {
			return "", fmt.Errorf("failed to get auth token: %w", err)
		}
		a.authResponseCache = resp
		a.authTimeMillis = time.Now().UnixMilli()
	}

	if token, ok := a.authResponseCache["Auth"]; ok && token != "" {
		return token, nil
	}

	return "", errors.New("auth response does not contain bearer token")
}

func (a *Api) getAuthToken() (map[string]string, error) {
	authDataValues, err := url.ParseQuery(a.authData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse auth data: %w", err)
	}

	authRequestData := url.Values{}
	for k, v := range authDataValues {
		authRequestData[k] = v
	}
	authRequestData.Set("app", "com.google.android.apps.photos")
	authRequestData.Set("callerPkg", "com.google.android.apps.photos")
	authRequestData.Set("consumerVersionCode", strconv.FormatInt(a.clientVersionCode, 10))
	authRequestData.Set("has_permission", "1")
	authRequestData.Set("pkgVersionCode", strconv.FormatInt(a.clientVersionCode, 10))
	if authRequestData.Get("sdk_version") == "" {
		authRequestData.Set("sdk_version", strconv.FormatInt(a.androidAPIVersion, 10))
	}
	authRequestData.Del("it_caveat_types")

	var tokenBinding *tokenBindingSession
	if alias := authRequestData.Get("token_binding_alias"); alias != "" {
		var assertionJWT string
		tokenBinding, assertionJWT, err = newTokenBindingSession(alias)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare token binding assertion: %w", err)
		}
		authRequestData.Set("assertion_jwt", assertionJWT)
	}

	gmsVersion := authRequestData.Get("google_play_services_version")
	if gmsVersion == "" {
		gmsVersion = "261631032"
	}
	authUA := authUserAgent(authRequestData, gmsVersion)
	stripTokenBindingPrivateParams(authRequestData)
	stripAuthPrivateParams(authRequestData)
	headers := map[string]string{
		"Accept-Encoding": "gzip",
		"app":             "com.google.android.apps.photos",
		"Connection":      "keep-alive",
		"Content-Type":    "application/x-www-form-urlencoded",
		"device":          authRequestData.Get("androidId"),
		"gmscoreFlow":     "29",
		"gmsversion":      gmsVersion,
		"User-Agent":      authUA,
	}

	req, err := http.NewRequest(
		"POST",
		"https://android.googleapis.com/auth",
		strings.NewReader(authRequestData.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth request failed after retries: %w", err)
	}
	defer resp.Body.Close()

	// Check for errors
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := readResponseBody(resp)
		return make(map[string]string), fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Handle gzip encoding if present
	reader, closeReader, err := responseReader(resp)
	if err != nil {
		return nil, err
	}
	defer closeReader()

	// Parse the response body
	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse the key=value response format
	parsedAuthResponse := make(map[string]string)
	for _, line := range strings.Split(string(bodyBytes), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			parsedAuthResponse[parts[0]] = parts[1]
		}
	}
	if err := decryptTokenEncryptedResponse(parsedAuthResponse, tokenBinding); err != nil {
		return nil, err
	}

	// Accept both legacy Auth= and new it= (encrypted) token formats
	token := parsedAuthResponse["Auth"]
	if token == "" {
		token = parsedAuthResponse["it"]
	}
	if token == "" {
		return nil, errors.New("auth response missing Auth or it token")
	}
	parsedAuthResponse["Auth"] = token
	if parsedAuthResponse["Expiry"] == "" {
		return nil, errors.New("auth response missing Expiry")
	}

	return parsedAuthResponse, nil
}

// Obtain a file upload token from the Google Photos API.
func (a *Api) GetUploadToken(shaHash []byte, fileSize int64, fileName string, collectionName string, width int, height int) (string, error) {
	bearerToken, err := a.BearerToken()
	if err != nil {
		return "", fmt.Errorf("failed to get bearer token: %w", err)
	}

	if err := a.initUploadSession(shaHash, bearerToken); err != nil {
		return "", fmt.Errorf("failed to initialize Photos upload session: %w", err)
	}

	serializedData := make([]byte, 0, len(collectionName)+32)
	serializedData = appendProtoVarintField(serializedData, 1, 2)
	serializedData = appendProtoVarintField(serializedData, 2, 1)
	serializedData = appendProtoVarintField(serializedData, 3, 1)
	serializedData = appendProtoVarintField(serializedData, 4, 3)
	if width > 0 {
		serializedData = appendProtoVarintField(serializedData, 5, uint64(width))
	}
	if height > 0 {
		serializedData = appendProtoVarintField(serializedData, 6, uint64(height))
	}
	serializedData = appendProtoVarintField(serializedData, 7, uint64(fileSize))
	serializedData = appendProtoStringField(serializedData, 9, collectionName)
	serializedData = appendProtoStringField(serializedData, 10, "\x00")

	// Prepare headers
	headers := map[string]string{
		"Accept-Encoding":         "gzip, deflate",
		"Accept-Language":         a.language,
		"Connection":              "keep-alive",
		"Content-Type":            "application/x-protobuf",
		"User-Agent":              a.userAgent,
		"Authorization":           "Bearer " + bearerToken,
		"X-Auth-Time":             strconv.FormatInt(a.authTimeMillis, 10),
		"X-Goog-Hash":             "sha1=" + encodeUploadSHA1(shaHash),
		"X-Goog-Upload-File-Name": fileName,
		"X-Upload-Content-Length": strconv.FormatInt(fileSize, 10),
	}

	// Create the request
	req, err := http.NewRequest(
		"POST",
		"https://photos.googleapis.com/data/upload/uploadmedia/interactive",
		bytes.NewReader(serializedData),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Make the request
	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check for errors
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := readResponseBody(resp)
		return "", fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Get the upload token from headers
	uploadToken := resp.Header.Get("X-GUploader-UploadID")
	if uploadToken == "" {
		return "", errors.New("response missing X-GUploader-UploadID header")
	}

	return uploadToken, nil
}

func (a *Api) initUploadSession(shaHash []byte, bearerToken string) error {
	serializedData := marshalUploadSessionInit(shaHash)

	headers := map[string]string{
		"Accept-Encoding":          "gzip, deflate",
		"Accept-Language":          a.language,
		"Authorization":            "Bearer " + bearerToken,
		"Connection":               "keep-alive",
		"Content-Type":             "application/x-protobuf",
		"User-Agent":               a.userAgent,
		"X-Auth-Time":              strconv.FormatInt(a.authTimeMillis, 10),
		"x-goog-ext-173412678-bin": "CgcIAxClARgC",
		"x-goog-ext-174067345-bin": "CgIIAQ==",
	}

	req, err := http.NewRequest(
		"POST",
		"https://photosdata-pa.googleapis.com/6439526531001121323/5084965799730810217",
		bytes.NewReader(serializedData),
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := readResponseBody(resp)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func marshalUploadSessionInit(shaHash []byte) []byte {
	hashField := make([]byte, 0, len(shaHash)+4)
	hashField = append(hashField, 0x0a, byte(len(shaHash)))
	hashField = append(hashField, shaHash...)
	hashField = append(hashField, 0x30, 0x01)

	inner := make([]byte, 0, len(hashField)+6)
	inner = append(inner, 0x0a, byte(len(hashField)))
	inner = append(inner, hashField...)
	inner = append(inner, 0x12, 0x02, 0x0a, 0x00)

	outer := make([]byte, 0, len(inner)+2)
	outer = append(outer, 0x0a, byte(len(inner)))
	outer = append(outer, inner...)
	return outer
}

func encodeUploadSHA1(shaHash []byte) string {
	return base64.StdEncoding.EncodeToString(shaHash)
}

func appendProtoStringField(data []byte, fieldNumber int, value string) []byte {
	data = appendProtoVarint(data, uint64(fieldNumber<<3|2))
	data = appendProtoVarint(data, uint64(len(value)))
	return append(data, value...)
}

func appendProtoVarintField(data []byte, fieldNumber int, value uint64) []byte {
	data = appendProtoVarint(data, uint64(fieldNumber<<3))
	return appendProtoVarint(data, value)
}

func appendProtoVarint(data []byte, value uint64) []byte {
	for value >= 0x80 {
		data = append(data, byte(value)|0x80)
		value >>= 7
	}
	return append(data, byte(value))
}

func responseReader(resp *http.Response) (io.Reader, func(), error) {
	if !strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		return resp.Body, func() {}, nil
	}

	reader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	return reader, func() { reader.Close() }, nil
}

func readResponseBody(resp *http.Response) ([]byte, error) {
	reader, closeReader, err := responseReader(resp)
	if err != nil {
		return nil, err
	}
	defer closeReader()
	return io.ReadAll(reader)
}

// Check library for existing files with the hash
func (a *Api) FindRemoteMediaByHash(shaHash []byte) (string, error) {
	// Get the bearer token
	bearerToken, err := a.BearerToken()
	if err != nil {
		return "", fmt.Errorf("failed to get bearer token: %w", err)
	}

	serializedData := marshalUploadSessionInit(shaHash)

	// Prepare headers
	headers := map[string]string{
		"Accept-Encoding":          "gzip, deflate",
		"Accept-Language":          a.language,
		"Authorization":            "Bearer " + bearerToken,
		"Connection":               "keep-alive",
		"Content-Type":             "application/x-protobuf",
		"User-Agent":               a.userAgent,
		"X-Auth-Time":              strconv.FormatInt(a.authTimeMillis, 10),
		"x-goog-ext-173412678-bin": "CgcIAxClARgC",
		"x-goog-ext-174067345-bin": "CgIIAQ==",
	}

	// Create the request
	req, err := http.NewRequest(
		"POST",
		"https://photosdata-pa.googleapis.com/6439526531001121323/5084965799730810217",
		bytes.NewReader(serializedData),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Make the request
	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check for errors
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := readResponseBody(resp)
		return "", fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	reader, closeReader, err := responseReader(resp)
	if err != nil {
		return "", err
	}
	defer closeReader()

	// Parse the response body
	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var pbResp generated.RemoteMatches
	if err := proto.Unmarshal(bodyBytes, &pbResp); err != nil {
		return "", fmt.Errorf("failed to unmarshal protobuf: %w", err)
	}

	mediaKey := pbResp.GetMediaKey()

	return mediaKey, nil
}

// UploadProgressCallback is called with progress updates during file upload
// attempt is 1-based (1 = first attempt, 2 = first retry, etc.)
type UploadProgressCallback func(bytesUploaded, bytesTotal int64, attempt int)

func (a *Api) UploadFile(ctx context.Context, filePath string, uploadToken string) (*generated.CommitToken, error) {
	return a.UploadFileWithProgress(ctx, filePath, uploadToken, nil)
}

func (a *Api) UploadFileWithProgress(ctx context.Context, filePath string, uploadToken string, onProgress UploadProgressCallback) (*generated.CommitToken, error) {
	// Get file size first (needed for progress tracking)
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("error getting file info: %w", err)
	}
	fileSize := fileInfo.Size()

	uploadURL := "https://photos.googleapis.com/data/upload/uploadmedia/interactive?upload_id=" + uploadToken
	retryConfig := DefaultRetryConfig()

	var lastErr error
	for attempt := 0; attempt <= retryConfig.MaxRetries; attempt++ {
		attemptNum := attempt + 1 // 1-based for display

		// Check context before each attempt
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// Wait before retry (skip on first attempt)
		if attempt > 0 {
			delay := CalculateBackoff(attempt-1, retryConfig)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		// Signal start of this attempt (resets progress on retry)
		if onProgress != nil {
			onProgress(0, fileSize, attemptNum)
		}

		// Open file fresh for each attempt - this is the key to not loading into memory
		file, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("error opening file: %w", err)
		}

		// Wrap file in progress reader if callback provided
		var reader io.Reader = file
		if onProgress != nil {
			reader = NewProgressReader(file, fileSize, func(bytesRead, total int64) {
				onProgress(bytesRead, total, attemptNum)
			})
		}

		result, err := a.doUploadRequest(ctx, uploadURL, reader, filePath, fileSize)
		file.Close() // Close file after request completes (success or fail)

		if err == nil {
			return result, nil
		}

		lastErr = err

		// Don't retry on context cancellation
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("upload failed after %d attempts: %w", retryConfig.MaxRetries+1, lastErr)
}

// doUploadRequest performs a single upload attempt
func (a *Api) doUploadRequest(ctx context.Context, uploadURL string, reader io.Reader, filePath string, fileSize int64) (*generated.CommitToken, error) {
	req, err := http.NewRequestWithContext(ctx, "PUT", uploadURL, reader)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.ContentLength = fileSize

	bearerToken, err := a.BearerToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get bearer token: %w", err)
	}

	contentType := mime.TypeByExtension(filepath.Ext(filePath))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", a.language)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", fileSize-1, fileSize))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", a.userAgent)
	req.Header.Set("X-Auth-Time", strconv.FormatInt(a.authTimeMillis, 10))

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check for non-success status codes (includes retryable 5xx/429 and non-retryable 4xx)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := readResponseBody(resp)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	reader, closeReader, err := responseReader(resp)
	if err != nil {
		return nil, err
	}
	defer closeReader()

	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var pbResp generated.CommitToken
	if err := proto.Unmarshal(bodyBytes, &pbResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal protobuf: %w", err)
	}

	return &pbResp, nil
}

// CommitUpload commits the upload to Google Photos
func (a *Api) CommitUpload(
	uploadResponseDecoded *generated.CommitToken,
	fileName string,
	sha1Hash []byte,
	uploadTimestamp int64,
) (string, error) {
	if uploadTimestamp == 0 {
		uploadTimestamp = time.Now().Unix()
	}

	var qualityVal int64 = 3
	if AppConfig.Saver {
		qualityVal = 1
		a.model = "Pixel 2"
	}

	if AppConfig.UseQuota {
		a.model = "Pixel 8"
	}

	unknownInt := int64(46000000)

	// Create the protobuf message
	protoBody := generated.CommitUpload{
		Field1: &generated.CommitUploadField1Type{
			Field1: &generated.CommitUploadField1TypeField1Type{
				Field1: uploadResponseDecoded.Field1,
				Field2: uploadResponseDecoded.Field2,
			},
			FileName: fileName,
			Sha1Hash: sha1Hash,
			Field4: &generated.CommitUploadField1TypeField4Type{
				FileLastModifiedTimestamp: uploadTimestamp,
				Field2:                    unknownInt,
			},
			Quality: qualityVal,
			Field10: 1,
		},
		Field2: &generated.CommitUploadField2Type{
			Model:             a.model,
			Make:              a.make,
			AndroidApiVersion: a.androidAPIVersion,
		},
		Field3: []byte{1, 3},
	}

	// Serialize the protobuf message
	serializedData, err := proto.Marshal(&protoBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal protobuf: %w", err)
	}

	retryConfig := DefaultRetryConfig()
	var lastErr error
	for attempt := 0; attempt <= retryConfig.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := CalculateBackoff(attempt-1, retryConfig)
			time.Sleep(delay)
		}
		mediaKey, err := a.doCommitRequest(serializedData)
		if err == nil {
			return mediaKey, nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("commit failed after %d attempts: %w", retryConfig.MaxRetries+1, lastErr)
}

func (a *Api) doCommitRequest(serializedData []byte) (string, error) {
	bearerToken, err := a.BearerToken()
	if err != nil {
		return "", fmt.Errorf("failed to get bearer token: %w", err)
	}

	headers := map[string]string{
		"accept-Encoding":          "gzip",
		"accept-Language":          a.language,
		"content-Type":             "application/x-protobuf",
		"user-Agent":               a.userAgent,
		"authorization":            "Bearer " + bearerToken,
		"x-auth-time":              strconv.FormatInt(a.authTimeMillis, 10),
		"x-goog-ext-173412678-bin": "CgcIAxClARgC",
		"x-goog-ext-174067345-bin": "CgIIAg==",
	}

	req, err := http.NewRequest("POST",
		"https://photosdata-pa.googleapis.com/6439526531001121323/16538846908252377752",
		bytes.NewReader(serializedData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := readResponseBody(resp)
		return "", fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	reader, closeReader, err := responseReader(resp)
	if err != nil {
		return "", err
	}
	defer closeReader()

	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var pbResp generated.CommitUploadResponse
	if err := proto.Unmarshal(bodyBytes, &pbResp); err != nil {
		return "", fmt.Errorf("failed to unmarshal protobuf: %w", err)
	}

	if pbResp.GetField1() == nil || pbResp.GetField1().GetField3() == nil {
		return "", fmt.Errorf("upload rejected by API: invalid response structure")
	}
	mediaKey := pbResp.GetField1().GetField3().GetMediaKey()
	if mediaKey == "" {
		return "", fmt.Errorf("upload rejected by API: no media key returned")
	}
	return mediaKey, nil
}

// CreateAlbum creates a new album with the given name and initial media items.
// Returns the album media key for subsequent AddMediaToAlbum calls.
func (a *Api) CreateAlbum(albumName string, mediaKeys []string) (string, error) {
	// Build media keys structure
	protoMediaKeys := make([]*generated.CreateAlbumField4Type, len(mediaKeys))
	for i, key := range mediaKeys {
		protoMediaKeys[i] = &generated.CreateAlbumField4Type{
			Field1: &generated.CreateAlbumField4TypeField1Type{
				MediaKey: key,
			},
		}
	}

	// Create the protobuf message
	protoBody := generated.CreateAlbum{
		AlbumName: albumName,
		Timestamp: time.Now().Unix(),
		Field3:    1,
		MediaKeys: protoMediaKeys,
		Field6:    &generated.CreateAlbumField6Type{},
		Field7:    &generated.CreateAlbumField7Type{Field1: 3},
		DeviceInfo: &generated.CreateAlbumField8Type{
			Model:             a.model,
			Make:              a.make,
			AndroidApiVersion: a.androidAPIVersion,
		},
	}

	// Serialize the protobuf message
	serializedData, err := proto.Marshal(&protoBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal protobuf: %w", err)
	}

	// Get the bearer token
	bearerToken, err := a.BearerToken()
	if err != nil {
		return "", fmt.Errorf("failed to get bearer token: %w", err)
	}

	// Prepare headers
	headers := map[string]string{
		"Accept-Encoding":          "gzip",
		"Accept-Language":          a.language,
		"Content-Type":             "application/x-protobuf",
		"User-Agent":               a.userAgent,
		"Authorization":            "Bearer " + bearerToken,
		"X-Auth-Time":              strconv.FormatInt(a.authTimeMillis, 10),
		"x-goog-ext-173412678-bin": "CgcIAhClARgC",
		"x-goog-ext-174067345-bin": "CgIIAg==",
	}

	// Create the request
	req, err := http.NewRequest(
		"POST",
		"https://photosdata-pa.googleapis.com/6439526531001121323/8386163679468898444",
		bytes.NewReader(serializedData),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Make the request
	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check for errors
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := readResponseBody(resp)
		return "", fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Handle gzip response if needed
	reader, closeReader, err := responseReader(resp)
	if err != nil {
		return "", err
	}
	defer closeReader()

	// Parse the response body
	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var pbResp generated.CreateAlbumResponse
	if err := proto.Unmarshal(bodyBytes, &pbResp); err != nil {
		return "", fmt.Errorf("failed to unmarshal protobuf: %w", err)
	}

	// Get album media key from response
	if pbResp.GetField1() == nil {
		return "", fmt.Errorf("create album failed: invalid response structure")
	}

	albumMediaKey := pbResp.GetField1().GetAlbumMediaKey()
	if albumMediaKey == "" {
		return "", fmt.Errorf("create album failed: no album media key returned")
	}

	return albumMediaKey, nil
}

// AddMediaToAlbum adds media items to an existing album.
func (a *Api) AddMediaToAlbum(albumMediaKey string, mediaKeys []string) error {
	// Create the protobuf message
	protoBody := generated.AddMediaToAlbum{
		MediaKeys:     mediaKeys,
		AlbumMediaKey: albumMediaKey,
		Field5:        &generated.AddMediaToAlbumField5Type{Field1: 2},
		DeviceInfo: &generated.AddMediaToAlbumField6Type{
			Model:             a.model,
			Make:              a.make,
			AndroidApiVersion: a.androidAPIVersion,
		},
		Timestamp: time.Now().Unix(),
	}

	// Serialize the protobuf message
	serializedData, err := proto.Marshal(&protoBody)
	if err != nil {
		return fmt.Errorf("failed to marshal protobuf: %w", err)
	}

	// Get the bearer token
	bearerToken, err := a.BearerToken()
	if err != nil {
		return fmt.Errorf("failed to get bearer token: %w", err)
	}

	// Prepare headers
	headers := map[string]string{
		"Accept-Encoding":          "gzip",
		"Accept-Language":          a.language,
		"Content-Type":             "application/x-protobuf",
		"User-Agent":               a.userAgent,
		"Authorization":            "Bearer " + bearerToken,
		"X-Auth-Time":              strconv.FormatInt(a.authTimeMillis, 10),
		"x-goog-ext-173412678-bin": "CgcIAhClARgC",
		"x-goog-ext-174067345-bin": "CgIIAg==",
	}

	// Create the request
	req, err := http.NewRequest(
		"POST",
		"https://photosdata-pa.googleapis.com/6439526531001121323/484917746253879292",
		bytes.NewReader(serializedData),
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Make the request
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check for errors
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := readResponseBody(resp)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
