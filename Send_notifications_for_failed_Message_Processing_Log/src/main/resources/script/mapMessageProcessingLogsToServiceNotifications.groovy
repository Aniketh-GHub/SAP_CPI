import com.sap.gateway.ip.core.customdev.util.Message
import groovy.json.JsonOutput
import groovy.transform.Field

import java.security.MessageDigest

@Field final String UTF_8 = 'UTF-8'
@Field final String NOT_AVAILABLE = 'N/A'
@Field final String LOG_PROPERTY_KEY = 'Log'
@Field final String CI_TENANT_BASE_URL_PROPERTY_KEY = "CI_TENANT_BASE_URL"
@Field final String SOURCE_EVENT_ID_STRATEGY_PROPERTY_KEY = "SOURCE_EVENT_ID_STRATEGY"
@Field final String CURRENT_TIME_FRAME_END_HEADER_NAME = "CURRENT_TIME_FRAME_END"
@Field final String CURRENT_TIME_FRAME_START_HEADER_NAME = "CURRENT_TIME_FRAME_START"

Message processData(Message message) {

	StringBuilder logMessage = new StringBuilder(getStringProperty(message, LOG_PROPERTY_KEY))
	String executionGuid = UUID.randomUUID().toString()
	logMessage.append("\nMap Message Process Logs to Service Notifications:\n")

	def messageProcessingLogs = new XmlSlurper(false, true).parse(message.getBody(Reader.class))
	def flowIdToMessageProcessingLog = messageProcessingLogs.MessageProcessingLog.groupBy { entry -> entry.IntegrationArtifact.Id.toString() }

	logMessage.append("Found '${messageProcessingLogs.MessageProcessingLog.size()}' failed messages\n")
	List<Event> events = []
	flowIdToMessageProcessingLog.each { String key, def value ->
		logMessage.append("Mapping '${value.size()}' failed messages for integration flow with id '${key}' to service notification\n")
		events.add(toNotification(key, value, message, executionGuid))
	}
	logMessage.append("Maped to '${events.size()}' service notifications\n")
	message.setProperty(LOG_PROPERTY_KEY, logMessage)
	message.setBody(JsonOutput.toJson(events))
	return message
}


Event toNotification(String flowId, def messages, Message message, String executionGuid) {

	String flowName = messages[0].IntegrationArtifact.Name.toString()
	String flowType = messages[0].IntegrationArtifact.Type.toString()
	String packageId = messages[0].IntegrationArtifact.PackageId.toString()
	String packageName = messages[0].IntegrationArtifact.PackageName.toString()
	String cpiTenantBaseUrl = getStringProperty(message, CI_TENANT_BASE_URL_PROPERTY_KEY)
	String currentTimeFrameEnd = getStringHeader(message, CURRENT_TIME_FRAME_END_HEADER_NAME)
	String currentTimeFrameStart = getStringHeader(message, CURRENT_TIME_FRAME_START_HEADER_NAME)
	String adjustedCpiTenantBaseUrl = cpiTenantBaseUrl.endsWith('/') ? cpiTenantBaseUrl.substring(0, cpiTenantBaseUrl.length() - 1) : cpiTenantBaseUrl
	String cpiMonitoringUrl = "${adjustedCpiTenantBaseUrl}/itspaces/shell/monitoring/Messages/%7B%22time%22:%22CUSTOM%22,%22from%22:%22${URLEncoder.encode(currentTimeFrameStart, UTF_8)}Z%22,%22to%22:%22${URLEncoder.encode(currentTimeFrameEnd, UTF_8)}Z%22,%22artifact%22:%22${URLEncoder.encode(flowId, UTF_8)}%22,%22status%22:%22FAILED%22%7D"
	String integrationFlowUrl = "${adjustedCpiTenantBaseUrl}/itspaces/shell/design/contentpackage/${URLEncoder.encode(packageId, UTF_8)}/integrationflows/${URLEncoder.encode(flowId, UTF_8)}"
	String sourceEventId = getSourceEventId(executionGuid, flowId, packageId, cpiTenantBaseUrl, message)

	Event event = new Event(
			eventType: "CPIIntegrationFlowExecutionFailure",
			resource: new Resource(
					resourceName: flowName,
					resourceType: flowType
			),
			severity: "INFO",
			category: "NOTIFICATION",
			subject: "CPI Integration Flow '${flowName}': Execution Failure",
			body: "There were '${messages.size()}' failures for the '${flowName}' integration flow within the time frame starting from '${currentTimeFrameStart}' and ending at '${currentTimeFrameEnd}'. ",
			tags: [
					'ans:detailsLink'                    : cpiMonitoringUrl,
					'cpi:IntegrationArtifact.Id'         : flowId,
					'cpi:IntegrationArtifact.Name'       : flowName,
					'cpi:IntegrationArtifact.PackageId'  : packageId?.trim() ? packageId : NOT_AVAILABLE,
					'cpi:IntegrationArtifact.PackageName': packageName?.trim() ? packageName : NOT_AVAILABLE,
					'cpi:IntegrationFlowUrl'             : packageId?.trim() ? integrationFlowUrl : NOT_AVAILABLE,
					'cpi:MessageFailureCount'            : messages.size()
			]
	)
	if (sourceEventId?.trim()) {
		event.tags.put('ans:sourceEventId', sourceEventId)
	}
	return event

}

String getSourceEventId(String executionGuid, String flowId, String packageId, String cpiTenantBaseUrl, Message message) {
	try {
		String sourceEventIdStrategy = getStringProperty(message, SOURCE_EVENT_ID_STRATEGY_PROPERTY_KEY)

		switch (sourceEventIdStrategy) {
			case 'PER_TENANT':
				return md5Digest(cpiTenantBaseUrl)
			case 'PER_EXECUTION':
				return md5Digest(executionGuid)
			case 'PER_INTEGRATION_FLOW':
				return md5Digest(flowId)
			case 'PER_PACKAGE':
				return packageId?.trim() ? md5Digest(packageId) : null
			case 'PER_PACKAGE_AND_EXECUTION':
				return packageId?.trim() ? md5Digest(packageId.concat(executionGuid)) : null
			default:
				return null
		}
	} catch (Exception e) {
		return null
	}
}

class Event {
	String eventType
	Resource resource
	String severity
	String category
	String subject
	String body
	Map<String, String> tags

}

class Resource {
	String resourceName
	String resourceType
}

static String md5Digest(String s) {
	return MessageDigest.getInstance("MD5").digest(s.bytes).encodeHex().toString().toUpperCase()
}

static String getStringProperty(Message message, String propertyName) {
	def propertyValue = message.getProperty(propertyName)
	return propertyValue != null ? propertyValue.toString() : null
}

static String getStringHeader(Message message, String headerName) {
	return message.getHeader(headerName, String.class)
}
