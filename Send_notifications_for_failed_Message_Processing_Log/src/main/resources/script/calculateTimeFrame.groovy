import com.sap.gateway.ip.core.customdev.util.Message
import groovy.transform.Field

import java.text.ParseException
import java.text.SimpleDateFormat

@Field final String TIME_ZONE = "UTC"
@Field final String TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss"
@Field final SimpleDateFormat DATE_FORMATTER = new SimpleDateFormat(TIME_FORMAT)
@Field final String LOG_PROPERTY_KEY = 'Log'
@Field final String LAST_TIME_FRAME_END_HEADER_NAME = "LAST_TIME_FRAME_END"
@Field final String CURRENT_TIME_FRAME_END_HEADER_NAME = "CURRENT_TIME_FRAME_END"
@Field final String CURRENT_TIME_FRAME_START_HEADER_NAME = "CURRENT_TIME_FRAME_START"
@Field final Integer MAX_TIME_FRAME_SIZE_MS = 72 * 60 * 60 * 1000

Message processData(Message message) {
	StringBuilder logMessage = new StringBuilder('Calculate Time Frame:\n')

	configureDateFormatter()
	Calendar now = Calendar.getInstance()

	String currentTimeFrameStart = DATE_FORMATTER.format(retrieveCurrentTimeFrameStart(message, now))
	String currentTimeFrameEnd = DATE_FORMATTER.format(retrieveCurrentTimeFrameEnd(now))

	logMessage.append("Executing for time frame: ${currentTimeFrameStart} - ${currentTimeFrameEnd}\n")
	message.setHeader(CURRENT_TIME_FRAME_START_HEADER_NAME, currentTimeFrameStart)
	message.setHeader(CURRENT_TIME_FRAME_END_HEADER_NAME, currentTimeFrameEnd)
	message.setProperty(LOG_PROPERTY_KEY, logMessage.toString())
	return message
}

void configureDateFormatter() {
	DATE_FORMATTER.setTimeZone(TimeZone.getTimeZone(TIME_ZONE))
}

Date retrieveCurrentTimeFrameStart(Message message, Calendar now) {
	String lastTimeFrameEnd = getStringHeader(message, LAST_TIME_FRAME_END_HEADER_NAME)
	if (lastTimeFrameEnd?.trim()) {
		return getCurrentTimeFrameStart(lastTimeFrameEnd, now)
	} else {
		return getDefaultCurrentTimeFrameStart(now)
	}
}

Date getCurrentTimeFrameStart(String lastTimeFrameEnd, Calendar now) {
	try {
		Date currentTimeFrameStart = DATE_FORMATTER.parse(lastTimeFrameEnd)

		return getTimeFrameSize(now.getTime(), currentTimeFrameStart) > MAX_TIME_FRAME_SIZE_MS ? getDefaultCurrentTimeFrameStart(now) : currentTimeFrameStart
	} catch (ParseException e) {
		return getDefaultCurrentTimeFrameStart(now)
	}
}

Date getDefaultCurrentTimeFrameStart(Calendar now) {
	Calendar nowClone = now.clone() as Calendar
	nowClone.add(Calendar.MILLISECOND, MAX_TIME_FRAME_SIZE_MS * -1)
	return nowClone.getTime()
}

static long getTimeFrameSize(Date to, Date from) {
	return to.getTime() - from.getTime()
}

static Date retrieveCurrentTimeFrameEnd(Calendar now) {
	return now.getTime()
}

static String getStringHeader(Message message, String headerName) {
	return message.getHeader(headerName, String.class)
}
