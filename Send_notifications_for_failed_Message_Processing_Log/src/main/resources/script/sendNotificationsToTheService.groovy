import com.sap.gateway.ip.core.customdev.util.Message
import com.sap.it.api.ITApiFactory
import com.sap.it.api.keystore.KeystoreService
import com.sap.it.api.securestore.SecureStoreService
import com.sap.it.api.securestore.UserCredential
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovy.transform.Field
import org.apache.http.client.config.RequestConfig
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpPost
import org.apache.http.entity.StringEntity
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClientBuilder
import org.apache.http.ssl.SSLContexts

import javax.net.ssl.SSLContext
import java.security.Key
import java.security.KeyStore
import java.security.cert.Certificate

@Field final String AUTHORIZATION_HEADER_NAME = 'Authorization'
@Field final String CONTENT_TYPE_HEADER_NAME = 'Content-Type'
@Field final String APPLICATION_JSON_UTF8_CONTENT_TYPE = 'application/json;charset=utf-8'
@Field final String TEXT_PLAIN_CONTENT_TYPE = 'text/plain'
@Field final String HTTP_METHOD_POST = 'POST'
@Field final String UTF_8 = 'UTF-8'
@Field final String LOG_PROPERTY_KEY = 'Log'
@Field final String ENABLE_LOG_PROPERTY_KEY = 'ENABLE_LOG'
@Field final String CREDENTIALS_TYPE_PROPERTY_KEY = 'sec:credential.kind'
@Field final String SERVICE_CREDENTIALS_NAME_PROPERTY_KEY = 'SERVICE_CREDENTIALS_NAME'
@Field final String SERVICE_RESOURCE_EVENTS_URL_PROPERTY_KEY = 'SERVICE_RESOURCE_EVENTS_URL'
@Field final String SERVICE_REQUEST_TIMEOUT_MINUTES_PROPERTY_KEY = 'SERVICE_REQUEST_TIMEOUT_MINUTES'
@Field final String ENABLE_CERTIFICATE_AUTHENTICATION_PROPERTY_KEY = 'ENABLE_CERTIFICATE_AUTHENTICATION'
@Field final String KEYSTORE_ALIAS_PROPERTY_KEY = 'KEYSTORE_ALIAS'
@Field final String OAUTH2_URL_PROPERTY_KEY = 'sec:server.url'
@Field final String BASIC_CREDENTIALS_TYPE = 'default'
@Field final String OAUTH2_CREDENTIALS_TYPE = 'oauth2:default'
@Field final String INVALID_CREDENTIALS_TYPE_ERROR_MESSAGE = 'Invalid credentials type. Required OAuth2 Client Credentials or Basic Authentication'
@Field final int SERVICE_SUCCESS_STATUS_CODE = 202
@Field final int OAUTH2_PROVIDER_SUCCESS_STATUS_CODE = 200
@Field final boolean DEFAULT_ENABLE_LOG = false
@Field final boolean DEFAULT_ENABLE_CERTIFICATE_AUTHENTICATION = false
@Field final int DEFAULT_SERVICE_REQUEST_TIMEOUT_MINUTES = 1

Message processData(Message message) {

	StringBuilder logMessage = new StringBuilder(getStringProperty(message, LOG_PROPERTY_KEY))
	logMessage.append("\nSend Notifications to the Service:\n")
	int requestTimeoutMinutes = getIntProperty(message, SERVICE_REQUEST_TIMEOUT_MINUTES_PROPERTY_KEY, DEFAULT_SERVICE_REQUEST_TIMEOUT_MINUTES)

	if (!getBooleanProperty(message, ENABLE_CERTIFICATE_AUTHENTICATION_PROPERTY_KEY, DEFAULT_ENABLE_CERTIFICATE_AUTHENTICATION)) {
		UserCredential credentials = retrieveCredentials(getStringProperty(message, SERVICE_CREDENTIALS_NAME_PROPERTY_KEY))

		String authorizationHeaderValue = retrieveAuthorizationHeaderValue(credentials, requestTimeoutMinutes)

		sendNotifications( //
				getStringProperty(message, SERVICE_RESOURCE_EVENTS_URL_PROPERTY_KEY), //
				requestTimeoutMinutes, //
				authorizationHeaderValue, //
				message.getBody().toString(), //
				logMessage //
		)
	} else {
		sendNotifications(
				getStringProperty(message, SERVICE_RESOURCE_EVENTS_URL_PROPERTY_KEY), //
				requestTimeoutMinutes, //
				retrieveCertificateChain(getStringProperty(message, KEYSTORE_ALIAS_PROPERTY_KEY)), //
				retrieveKey(getStringProperty(message, KEYSTORE_ALIAS_PROPERTY_KEY)), //
				message.getBody().toString(), //
				logMessage //
		)
	}

	message.setProperty(LOG_PROPERTY_KEY, logMessage.toString())
	attachLogs(message, logMessage)
	return message
}

static UserCredential retrieveCredentials(String credentialsName) {
	return ITApiFactory.getService(SecureStoreService.class, null).getUserCredential(credentialsName)
}

static Certificate[] retrieveCertificateChain(String credentialsName) {
	return ITApiFactory.getService(KeystoreService.class, null).getCertificateChain(credentialsName)
}

static Key retrieveKey(String credentialsName) {
	return ITApiFactory.getService(KeystoreService.class, null).getKey(credentialsName)
}

String retrieveAuthorizationHeaderValue(UserCredential credentials, int requestTimeoutMinutes) {
	String credentialsType = credentials.getCredentialProperties().get(CREDENTIALS_TYPE_PROPERTY_KEY)
	if (credentialsType == BASIC_CREDENTIALS_TYPE) {
		String base64EncodedCredentials = toBase64EncodedCredentials(credentials)
		return "Basic ${base64EncodedCredentials}"
	} else if (credentialsType == OAUTH2_CREDENTIALS_TYPE) {
		String accessToken = obtainOAuth2Token(credentials, requestTimeoutMinutes)
		return "Bearer ${accessToken}"
	} else {
		throw new Exception(INVALID_CREDENTIALS_TYPE_ERROR_MESSAGE)
	}
}

String obtainOAuth2Token(UserCredential credentials, int requestTimeoutMinutes) {
	String base64EncodedCredentials = toBase64EncodedCredentials(credentials)
	URLConnection postRequest = new URL(credentials.getCredentialProperties().get(OAUTH2_URL_PROPERTY_KEY)).openConnection()
	postRequest.setConnectTimeout(minutesToMilliseconds(requestTimeoutMinutes))
	postRequest.setReadTimeout(minutesToMilliseconds(requestTimeoutMinutes))
	postRequest.setRequestMethod(HTTP_METHOD_POST)
	postRequest.setDoOutput(true)
	postRequest.setRequestProperty(AUTHORIZATION_HEADER_NAME, "Basic ${base64EncodedCredentials}")

	assert postRequest.getResponseCode() == OAUTH2_PROVIDER_SUCCESS_STATUS_CODE

	return new JsonSlurper().parseText(postRequest.getInputStream().getText()).access_token.toString()
}

void sendNotifications(String urlString, int requestTimeoutMinutes, String authorizationHeaderValue, String eventsAsJsonString, StringBuilder logMessage) {
	URL url = new URL(urlString)
	def events = new JsonSlurper().parseText(eventsAsJsonString)
	logMessage.append("Sending notifications to the service\n")
	events.each { event -> sendNotification(url, requestTimeoutMinutes, authorizationHeaderValue, JsonOutput.toJson(event)) }
}

static CloseableHttpClient createHttpClient(SSLContext sslContext, int requestTimeoutMinutes) {
	RequestConfig requestConfig = RequestConfig.custom() //
			.setConnectTimeout(minutesToMilliseconds(requestTimeoutMinutes)) //
			.setSocketTimeout(minutesToMilliseconds(requestTimeoutMinutes)) //
			.build()

	return HttpClientBuilder.create() //
			.setSSLContext(sslContext) //
			.setDefaultRequestConfig(requestConfig) //
			.build()

}

void sendNotifications(String urlString, int requestTimeoutMinutes, Certificate[] certificate, Key privateKey, String eventsAsJsonString, StringBuilder logMessage) {
	SSLContext sslContext = createSslContextWithCertificate(certificate, privateKey)
	def events = new JsonSlurper().parseText(eventsAsJsonString)
	logMessage.append("Sending notifications to the service using certificate authentication\n")

	CloseableHttpClient httpClient = createHttpClient(sslContext, requestTimeoutMinutes)

	httpClient.withCloseable {
		events.each { event -> sendNotification(urlString, httpClient, JsonOutput.toJson(event)) }
	}
}

void sendNotification(URL url, int requestTimeoutMinutes, String authorizationHeaderValue, String body) {
	URLConnection postRequest = url.openConnection()
	postRequest.setConnectTimeout(minutesToMilliseconds(requestTimeoutMinutes))
	postRequest.setReadTimeout(minutesToMilliseconds(requestTimeoutMinutes))
	postRequest.setRequestMethod(HTTP_METHOD_POST)
	postRequest.setDoOutput(true)
	postRequest.setRequestProperty(AUTHORIZATION_HEADER_NAME, authorizationHeaderValue)
	postRequest.setRequestProperty(CONTENT_TYPE_HEADER_NAME, APPLICATION_JSON_UTF8_CONTENT_TYPE)
	postRequest.getOutputStream().write(body.getBytes(UTF_8))

	assert postRequest.getResponseCode() == SERVICE_SUCCESS_STATUS_CODE
}

void sendNotification(String url, CloseableHttpClient httpClient, String body) {
	HttpPost request = new HttpPost(url)
	request.setEntity(new StringEntity(body))
	request.setHeader(CONTENT_TYPE_HEADER_NAME, APPLICATION_JSON_UTF8_CONTENT_TYPE)

	CloseableHttpResponse response = httpClient.execute(request)

	response.withCloseable {
		assert response.getStatusLine().getStatusCode() == SERVICE_SUCCESS_STATUS_CODE
	}
}

void attachLogs(Message message, StringBuilder logMessage) {
	if (getBooleanProperty(message, ENABLE_LOG_PROPERTY_KEY, DEFAULT_ENABLE_LOG)) {
		messageLogFactory.getMessageLog(message).addAttachmentAsString(LOG_PROPERTY_KEY, logMessage.toString(), TEXT_PLAIN_CONTENT_TYPE)
	}
}

KeyStore generateKeyStore(Certificate[] certificates, Key key) throws Exception {
	KeyStore keyStore = KeyStore.getInstance("JKS")

	keyStore.load(null, "".toCharArray())
	keyStore.setKeyEntry("Key entry", key, "".toCharArray(), certificates)

	return keyStore
}

SSLContext createSslContextWithCertificate(Certificate[] certificateResponse, Key privateKey) {
	KeyStore keyStore = generateKeyStore(certificateResponse, privateKey)

	return SSLContexts.custom() //
			.loadKeyMaterial(keyStore, "".toCharArray()) //
			.build()
}

static int getIntProperty(Message message, String propertyName, int defaultValue) {
	String propertyValue = getStringProperty(message, propertyName)
	return propertyValue != null && propertyValue.isInteger() ? propertyValue.toInteger() : defaultValue
}

static boolean getBooleanProperty(Message message, String propertyName, boolean defaultValue) {
	String propertyValue = getStringProperty(message, propertyName)
	return propertyValue != null ? propertyValue.toBoolean() : defaultValue
}

static String getStringProperty(Message message, String propertyName) {
	def propertyValue = message.getProperty(propertyName)
	return propertyValue != null ? propertyValue.toString() : null
}

static String toBase64EncodedCredentials(UserCredential credentials) {
	return (credentials.getUsername() + ":" + credentials.getPassword()).getBytes().encodeBase64().toString()
}

static int minutesToMilliseconds(int minutes) {
	return minutes * 60 * 1000
}