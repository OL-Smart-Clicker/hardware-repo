#include <WiFiS3.h>
#include <ArduinoMqttClient.h>
#include <ArduinoJson.h>
#include <WiFiUdp.h>
#include <NTPClient.h>
#include <ArduinoHttpClient.h>
#include <SHA256.h> // For HMAC-SHA256
#include <Base64.h> // For base64 encoding/decoding
#include "secrets.h"

// WiFi credentials
const char *ssid = SECRET_SSID;
const char *password = SECRET_PASS;

// DPS configuration
const char *dps_global_endpoint = SECRET_DPS_GLOBAL_ENDPOINT;
const char *dps_id_scope = SECRET_DPS_ID_SCOPE; // Your DPS ID Scope
char device_registration_id[32];
const char *enrollment_group_key = SECRET_DPS_SYMMETRIC_KEY; // Base64 encoded

// Variables populated after DPS registration
char iot_hub_hostname[128];
char device_id[64];
unsigned long sas_token_expiry;

// Network clients
WiFiSSLClient wifiClient;
WiFiUDP ntpUDP;
NTPClient timeClient(ntpUDP, "pool.ntp.org");
HttpClient httpClient(wifiClient, dps_global_endpoint, 443);
MqttClient mqttClient(wifiClient);

unsigned long lastMessage = 0;
const unsigned long messageInterval = 5000;

// --- Key Derivation ---
String deriveDeviceKey(const char *groupKeyB64, const char *regId)
{
  char groupKeyBuf[128];
  strncpy(groupKeyBuf, groupKeyB64, sizeof(groupKeyBuf));
  groupKeyBuf[sizeof(groupKeyBuf) - 1] = '\0';

  int decodedLen = Base64.decodedLength(groupKeyBuf, strlen(groupKeyB64));
  uint8_t decodedKey[decodedLen];
  Base64.decode((char *)decodedKey, groupKeyBuf, strlen(groupKeyB64));

  uint8_t hmacResult[32];
  SHA256 sha256;
  sha256.resetHMAC(decodedKey, decodedLen);
  sha256.update((const uint8_t *)regId, strlen(regId));
  sha256.finalizeHMAC(decodedKey, decodedLen, hmacResult, sizeof(hmacResult));

  int encodedLen = Base64.encodedLength(sizeof(hmacResult));
  char encodedResult[encodedLen + 1];
  Base64.encode(encodedResult, (char *)hmacResult, sizeof(hmacResult));
  encodedResult[encodedLen] = '\0';
  return String(encodedResult);
}

void generateDeviceCredentials()
{
  uint8_t mac[6];
  WiFi.macAddress(mac);
  char macStr[13];
  for (int i = 0; i < 6; i++)
  {
    sprintf(macStr + i * 2, "%02X", mac[i]);
  }
  snprintf(device_registration_id, sizeof(device_registration_id), "arduino-%s", macStr);
}

// --- WiFi and Time ---
void connectToWiFi()
{
  Serial.print("Connecting to WiFi...");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED || WiFi.localIP() == IPAddress(0, 0, 0, 0))
  {
    delay(1000);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("WiFi connected!");
}

void initializeTime()
{
  Serial.print("Synchronizing time...");
  timeClient.begin();
  while (!timeClient.update())
  {
    Serial.print(".");
    delay(1000);
  }
  Serial.println();
  Serial.print("Current time: ");
  Serial.println(timeClient.getFormattedTime());
}

// --- DPS Registration ---
String generateDPSSASToken(const String &deviceKey)
{
  unsigned long expiry = timeClient.getEpochTime() + 3600;
  String resource = String(dps_id_scope) + "/registrations/" + String(device_registration_id);
  String resourceCopy = "" + resource;
  String stringToSign = urlEncode(resource) + "\n" + String(expiry);

  // Xander Base64 requires non-const char* input, so copy to buffer
  char deviceKeyBuf[128];
  strncpy(deviceKeyBuf, deviceKey.c_str(), sizeof(deviceKeyBuf));
  deviceKeyBuf[sizeof(deviceKeyBuf) - 1] = '\0';

  int decodedLen = Base64.decodedLength(deviceKeyBuf, strlen(deviceKeyBuf));
  uint8_t decodedKey[decodedLen];
  Base64.decode((char *)decodedKey, deviceKeyBuf, strlen(deviceKeyBuf));

  uint8_t hmacResult[32];
  SHA256 sha256;
  sha256.resetHMAC(decodedKey, decodedLen);
  sha256.update((const uint8_t *)stringToSign.c_str(), stringToSign.length());
  sha256.finalizeHMAC(decodedKey, decodedLen, hmacResult, sizeof(hmacResult));

  int encodedLen = Base64.encodedLength(sizeof(hmacResult));
  char encodedResult[encodedLen + 1];
  Base64.encode(encodedResult, (char *)hmacResult, sizeof(hmacResult));
  encodedResult[encodedLen] = '\0';

  String sasToken = "SharedAccessSignature sr=" + urlEncode(resourceCopy) +
                    "&sig=" + urlEncode(String(encodedResult)) +
                    "&se=" + String(expiry);
  return sasToken;
}

bool registerWithDPS(const String &deviceKey)
{
  Serial.println("Starting DPS group enrollment registration...");
  String dps_sas_token = generateDPSSASToken(deviceKey);

  StaticJsonDocument<200> registrationDoc;
  registrationDoc["registrationId"] = device_registration_id;
  char registrationPayload[256];
  serializeJson(registrationDoc, registrationPayload);

  String dpsPath = "/";
  dpsPath += dps_id_scope;
  dpsPath += "/registrations/";
  dpsPath += device_registration_id;
  dpsPath += "/register?api-version=2021-10-01";

  httpClient.beginRequest();
  httpClient.put(dpsPath);
  httpClient.sendHeader("Content-Type", "application/json");
  httpClient.sendHeader("Content-Length", strlen(registrationPayload));
  httpClient.sendHeader("Authorization", dps_sas_token);
  httpClient.sendHeader("User-Agent", "Arduino-DPS-Group/1.0");
  httpClient.write((const byte *)registrationPayload, strlen(registrationPayload));
  httpClient.endRequest();

  int statusCode = httpClient.responseStatusCode();
  String response = httpClient.responseBody();

  if (statusCode == 202)
  {
    StaticJsonDocument<512> doc;
    DeserializationError error = deserializeJson(doc, response);

    if (!error && doc.containsKey("operationId"))
    {
      String operationId = doc["operationId"].as<String>();
      return pollDPSRegistrationStatus(deviceKey, operationId);
    }
    else
    {
      Serial.println("Failed DPS registration!");
      return false;
    }
  }
  else if (statusCode == 200)
    return parseDPSResponse(response);
  return false;
}

bool pollDPSRegistrationStatus(const String &deviceKey, String operation_id)
{
  Serial.println("Polling DPS registration status...");
  for (int attempt = 0; attempt < 10; attempt++)
  {
    delay(2000);
    String dpsPath = "/";
    dpsPath += dps_id_scope;
    dpsPath += "/registrations/";
    dpsPath += device_registration_id;
    dpsPath += "/operations/";
    dpsPath += operation_id;
    dpsPath += "?api-version=2021-10-01";

    String dps_sas_token = generateDPSSASToken(deviceKey);

    httpClient.beginRequest();
    httpClient.get(dpsPath);
    httpClient.sendHeader("Authorization", dps_sas_token);
    httpClient.sendHeader("User-Agent", "Arduino-DPS-Group/1.0");
    httpClient.endRequest();

    int statusCode = httpClient.responseStatusCode();
    String response = httpClient.responseBody();
    if (statusCode == 200)
      return parseDPSResponse(response);
    Serial.print("Polling attempt ");
    Serial.print(attempt + 1);
    Serial.print(", status: ");
    Serial.println(statusCode);
  }
  return false;
}

bool parseDPSResponse(String response)
{
  StaticJsonDocument<512> doc;
  DeserializationError error = deserializeJson(doc, response);
  if (error)
  {
    Serial.print("JSON parsing failed: ");
    Serial.println(error.c_str());
    return false;
  }
  if (doc["status"] == "assigned")
  {
    String assignedHub = doc["registrationState"]["assignedHub"];
    String deviceId = doc["registrationState"]["deviceId"];
    assignedHub.toCharArray(iot_hub_hostname, sizeof(iot_hub_hostname));
    deviceId.toCharArray(device_id, sizeof(device_id));
    Serial.print("Assigned to IoT Hub!");
    return true;
  }
  return false;
}

// --- SAS Token for IoT Hub ---
String generateSASToken(const String &deviceKey)
{
  unsigned long expiry = timeClient.getEpochTime() + 3600;
  sas_token_expiry = expiry;
  String resource = String(iot_hub_hostname) + "/devices/" + String(device_id);
  String resourceCopy = "" + resource;
  String stringToSign = urlEncode(resource) + "\n" + String(expiry);

  // Copy deviceKey to a mutable buffer
  char deviceKeyBuf[128];
  strncpy(deviceKeyBuf, deviceKey.c_str(), sizeof(deviceKeyBuf));
  deviceKeyBuf[sizeof(deviceKeyBuf) - 1] = '\0';

  int decodedLen = Base64.decodedLength(deviceKeyBuf, strlen(deviceKeyBuf));
  uint8_t decodedKey[decodedLen];
  Base64.decode((char *)decodedKey, deviceKeyBuf, strlen(deviceKeyBuf));

  uint8_t hmacResult[32];
  SHA256 sha256;
  sha256.resetHMAC(decodedKey, decodedLen);
  sha256.update((const uint8_t *)stringToSign.c_str(), stringToSign.length());
  sha256.finalizeHMAC(decodedKey, decodedLen, hmacResult, sizeof(hmacResult));

  int encodedLen = Base64.encodedLength(sizeof(hmacResult));
  char encodedResult[encodedLen + 1];
  Base64.encode(encodedResult, (char *)hmacResult, sizeof(hmacResult));
  encodedResult[encodedLen] = '\0';

  String sasToken = "SharedAccessSignature sr=" + urlEncode(resourceCopy) +
                    "&sig=" + urlEncode(String(encodedResult)) +
                    "&se=" + String(expiry);
  Serial.println("Generated new SAS token!");
  return sasToken;
}

String urlEncode(String str)
{
  String encoded = "";
  for (int i = 0; i < str.length(); i++)
  {
    char c = str.charAt(i);
    if (isAlphaNumeric(c) || c == '-' || c == '_' || c == '.' || c == '~')
    {
      encoded += c;
    }
    else
    {
      encoded += "%";
      if (c < 16)
        encoded += "0";
      encoded += String((unsigned char)c, HEX);
    }
  }
  return encoded;
}

// --- MQTT IoT Hub ---
void connectToIoTHub(const String &deviceKey)
{
  String username = String(iot_hub_hostname) + "/" + String(device_id) + "/?api-version=2020-09-30";
  String sas_token = generateSASToken(deviceKey);
  mqttClient.setId(device_id);
  mqttClient.setUsernamePassword(username.c_str(), sas_token);
  Serial.println("Connecting to Azure IoT Hub via MQTT...");
  while (!mqttClient.connect(iot_hub_hostname, 8883))
  {
    Serial.print("Failed to connect, error code: ");
    Serial.println(mqttClient.connectError());
    delay(1000);
  }
  Serial.println("Connected to Azure IoT Hub!");
}

void sendTelemetry()
{
  String topic = "devices/" + String(device_id) + "/messages/events/";
  StaticJsonDocument<200> doc;
  doc["deviceId"] = device_id;
  doc["temperature"] = 20.0 + random(0, 100) / 10.0;
  doc["humidity"] = 40.0 + random(0, 400) / 10.0;
  doc["timestamp"] = timeClient.getEpochTime();
  char payload[256];
  serializeJson(doc, payload);
  Serial.print("Sending telemetry...");
  mqttClient.beginMessage(topic);
  mqttClient.print(payload);
  mqttClient.endMessage();
  Serial.println("Telemetry sent!");
}

// --- Arduino setup and loop ---
void setup()
{
  Serial.begin(9600);
  delay(2000);

  Serial.println("Starting...");

  connectToWiFi();
  initializeTime();
  generateDeviceCredentials();

  // Derive device key from enrollment group key and registration ID
  String deviceKey = deriveDeviceKey(enrollment_group_key, device_registration_id);

  if (registerWithDPS(deviceKey))
  {
    Serial.println("DPS registration successful!");
    generateSASToken(deviceKey);
    connectToIoTHub(deviceKey);
  }
  else
  {
    Serial.println("DPS registration failed!");
    while (true)
      ;
  }
}

void loop()
{
  mqttClient.poll();

  if (timeClient.getEpochTime() >= (sas_token_expiry - 300))
  {
    Serial.println("Renewing SAS token...");
    String deviceKey = deriveDeviceKey(enrollment_group_key, device_registration_id);
    generateSASToken(deviceKey);
    connectToIoTHub(deviceKey);
  }

  if (!mqttClient.connected())
  {
    Serial.println("MQTT disconnected, reconnecting...");
    String deviceKey = deriveDeviceKey(enrollment_group_key, device_registration_id);
    generateSASToken(deviceKey);
    connectToIoTHub(deviceKey);
  }

  if (millis() - lastMessage > messageInterval)
  {
    sendTelemetry();
    lastMessage = millis();
  }
  delay(100);
}
