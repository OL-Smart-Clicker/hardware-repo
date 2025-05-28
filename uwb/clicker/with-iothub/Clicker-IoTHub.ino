/**
 * UWB Tag with Azure IoT Hub Integration
 * Measures distances to anchors and sends telemetry to Azure IoT Hub
 */

#include <SPI.h>
#include "DW1000Ranging.h"
#include <WiFiS3.h>
#include <ArduinoMqttClient.h>
#include <ArduinoJson.h>
#include <WiFiUdp.h>
#include <NTPClient.h>
#include <ArduinoHttpClient.h>
#include <SHA256.h>
#include <Base64.h>
#include <algorithm> // For sort()
#include "secrets.h"

// UWB Configuration
const uint8_t PIN_RST = 7;
const uint8_t PIN_IRQ = 8; // Changed to valid interrupt pin for R4
const uint8_t PIN_SS = 10;
const uint8_t UWB_DEVICE_ID = 10;
const uint8_t UWB_NETWORK_ID = 10;

// Define anchor IDs
const uint16_t ANCHOR_1 = 1;
const uint16_t ANCHOR_2 = 2;
const uint16_t ANCHOR_3 = 3;

// Measurement configuration
const uint8_t MAX_MEASUREMENTS = 20;
const uint8_t OUTLIERS_TO_REMOVE = 3;

// Measurement buffers for each anchor
float measurements_A1[MAX_MEASUREMENTS];
float measurements_A2[MAX_MEASUREMENTS];
float measurements_A3[MAX_MEASUREMENTS];
uint8_t measurementIndex_A1 = 0;
uint8_t measurementIndex_A2 = 0;
uint8_t measurementIndex_A3 = 0;

// Latest filtered distances for telemetry
float latest_distance_A1 = 0.0;
float latest_distance_A2 = 0.0;
float latest_distance_A3 = 0.0;
bool has_new_data = false;

// WiFi and Azure IoT Hub Configuration
const char *ssid = SECRET_SSID;
const char *password = SECRET_PASS;
const char *dps_global_endpoint = SECRET_DPS_GLOBAL_ENDPOINT;
const char *dps_id_scope = SECRET_DPS_ID_SCOPE;
char device_registration_id[32];
const char *enrollment_group_key = SECRET_DPS_SYMMETRIC_KEY;

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
const unsigned long messageInterval = 10000; // Send every 10 seconds

// Azure IoT Hub Functions (from your colleague's code)
String deriveDeviceKey(const char *groupKeyB64, const char *regId) {
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

void generateDeviceCredentials() {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  char macStr[13];
  for (int i = 0; i < 6; i++) {
    sprintf(macStr + i * 2, "%02X", mac[i]);
  }
  snprintf(device_registration_id, sizeof(device_registration_id), "uwb-tag-%s", macStr);
}

void connectToWiFi() {
  Serial.print("Connecting to WiFi...");
  if (password == "") {
    WiFi.begin(ssid);
  }
  else {
    WiFi.begin(ssid, password);
  }
  while (WiFi.status() != WL_CONNECTED || WiFi.localIP() == IPAddress(0, 0, 0, 0)) {
    delay(1000);
    Serial.print(".");
  }
  Serial.println();
  Serial.println("WiFi connected!");
}

void initializeTime() {
  Serial.print("Synchronizing time...");
  timeClient.begin();
  while (!timeClient.update()) {
    Serial.print(".");
    delay(1000);
  }
  Serial.println();
  Serial.print("Current time: ");
  Serial.println(timeClient.getFormattedTime());
}

String urlEncode(String str) {
  String encoded = "";
  for (int i = 0; i < str.length(); i++) {
    char c = str.charAt(i);
    if (isAlphaNumeric(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      encoded += c;
    } else {
      encoded += "%";
      if (c < 16) encoded += "0";
      encoded += String((unsigned char)c, HEX);
    }
  }
  return encoded;
}

String generateDPSSASToken(const String &deviceKey) {
  unsigned long expiry = timeClient.getEpochTime() + 3600;
  String resource = String(dps_id_scope) + "/registrations/" + String(device_registration_id);
  String resourceCopy = "" + resource;
  String stringToSign = urlEncode(resource) + "\n" + String(expiry);

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

bool parseDPSResponse(String response) {
  StaticJsonDocument<512> doc;
  DeserializationError error = deserializeJson(doc, response);
  if (error) {
    Serial.print("JSON parsing failed: ");
    Serial.println(error.c_str());
    return false;
  }
  if (doc["status"] == "assigned") {
    String assignedHub = doc["registrationState"]["assignedHub"];
    String deviceIdStr = doc["registrationState"]["deviceId"];
    assignedHub.toCharArray(iot_hub_hostname, sizeof(iot_hub_hostname));
    deviceIdStr.toCharArray(device_id, sizeof(device_id));
    Serial.println("Assigned to IoT Hub!");
    return true;
  }
  return false;
}

bool pollDPSRegistrationStatus(const String &deviceKey, String operation_id) {
  Serial.println("Polling DPS registration status...");
  for (int attempt = 0; attempt < 10; attempt++) {
    delay(2000);
    String dpsPath = "/" + String(dps_id_scope) + "/registrations/" + 
                     String(device_registration_id) + "/operations/" + 
                     operation_id + "?api-version=2021-10-01";

    String dps_sas_token = generateDPSSASToken(deviceKey);

    httpClient.beginRequest();
    httpClient.get(dpsPath);
    httpClient.sendHeader("Authorization", dps_sas_token);
    httpClient.sendHeader("User-Agent", "Arduino-DPS-Group/1.0");
    httpClient.endRequest();

    int statusCode = httpClient.responseStatusCode();
    String response = httpClient.responseBody();
    if (statusCode == 200) return parseDPSResponse(response);
    
    Serial.print("Polling attempt ");
    Serial.print(attempt + 1);
    Serial.print(", status: ");
    Serial.println(statusCode);
  }
  return false;
}

bool registerWithDPS(const String &deviceKey) {
  Serial.println("Starting DPS group enrollment registration...");
  String dps_sas_token = generateDPSSASToken(deviceKey);

  StaticJsonDocument<200> registrationDoc;
  registrationDoc["registrationId"] = device_registration_id;
  char registrationPayload[256];
  serializeJson(registrationDoc, registrationPayload);

  String dpsPath = "/" + String(dps_id_scope) + "/registrations/" + 
                   String(device_registration_id) + "/register?api-version=2021-10-01";

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

  if (statusCode == 202) {
    StaticJsonDocument<512> doc;
    DeserializationError error = deserializeJson(doc, response);
    if (!error && doc.containsKey("operationId")) {
      String operationId = doc["operationId"].as<String>();
      return pollDPSRegistrationStatus(deviceKey, operationId);
    } else {
      Serial.println("Failed DPS registration!");
      return false;
    }
  } else if (statusCode == 200) {
    return parseDPSResponse(response);
  }
  return false;
}

String generateSASToken(const String &deviceKey) {
  unsigned long expiry = timeClient.getEpochTime() + 3600;
  sas_token_expiry = expiry;
  String resource = String(iot_hub_hostname) + "/devices/" + String(device_id);
  String resourceCopy = "" + resource;
  String stringToSign = urlEncode(resource) + "\n" + String(expiry);

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

void connectToIoTHub(const String &deviceKey) {
  String username = String(iot_hub_hostname) + "/" + String(device_id) + "/?api-version=2020-09-30";
  String sas_token = generateSASToken(deviceKey);
  mqttClient.setId(device_id);
  mqttClient.setUsernamePassword(username.c_str(), sas_token);
  Serial.println("Connecting to Azure IoT Hub via MQTT...");
  while (!mqttClient.connect(iot_hub_hostname, 8883)) {
    Serial.print("Failed to connect, error code: ");
    Serial.println(mqttClient.connectError());
    delay(1000);
  }
  Serial.println("Connected to Azure IoT Hub!");
}

// UWB Functions
void processAndPrintAverage(uint16_t anchorID, float* measurements, uint8_t& index) {
  std::sort(measurements, measurements + MAX_MEASUREMENTS);
  
  float sum = 0;
  for(uint8_t i = OUTLIERS_TO_REMOVE; i < MAX_MEASUREMENTS - OUTLIERS_TO_REMOVE; i++) {
    sum += measurements[i];
  }
  
  float average = sum / (MAX_MEASUREMENTS - 2*OUTLIERS_TO_REMOVE);
  
  Serial.print("Anchor ");
  Serial.print(anchorID);
  Serial.print(" filtered average: ");
  Serial.print(average, 3);
  Serial.println(" m");
  
  // Store latest distance for telemetry
  switch(anchorID) {
    case ANCHOR_1: latest_distance_A1 = average; break;
    case ANCHOR_2: latest_distance_A2 = average; break;
    case ANCHOR_3: latest_distance_A3 = average; break;
  }
  has_new_data = true;
  
  index = 0;
}

void newRange() {
  DW1000Device* device = DW1000Ranging.getDistantDevice();
  uint16_t anchorID = device->getShortAddress();
  float range = device->getRange();
  
  switch(anchorID) {
    case ANCHOR_1:
      measurements_A1[measurementIndex_A1++] = range;
      Serial.print("Measured distance from A1: "); Serial.println(range);
      if(measurementIndex_A1 >= MAX_MEASUREMENTS) {
        processAndPrintAverage(ANCHOR_1, measurements_A1, measurementIndex_A1);
      }
      break;
      
    case ANCHOR_2:
      measurements_A2[measurementIndex_A2++] = range;
      Serial.print("Measured distance from A2: "); Serial.println(range);
      if(measurementIndex_A2 >= MAX_MEASUREMENTS) {
        processAndPrintAverage(ANCHOR_2, measurements_A2, measurementIndex_A2);
      }
      break;
      
    case ANCHOR_3:
      measurements_A3[measurementIndex_A3++] = range;
      Serial.print("Measured distance from A3: "); Serial.println(range);
      if(measurementIndex_A3 >= MAX_MEASUREMENTS) {
        processAndPrintAverage(ANCHOR_3, measurements_A3, measurementIndex_A3);
      }
      break;
      
    default:
      Serial.print("Unknown anchor: ");
      Serial.println(anchorID);
      return;
  }
}

void newDevice(DW1000Device* device) {
  Serial.print("ranging init; 1 device added ! -> ");
  Serial.print(" short:");
  Serial.println(device->getShortAddress(), HEX);
}

void inactiveDevice(DW1000Device* device) {
  Serial.print("delete inactive device: ");
  Serial.println(device->getShortAddress(), HEX);
}

void sendUWBTelemetry() {
  String topic = "devices/" + String(device_id) + "/messages/events/";
  StaticJsonDocument<400> doc;
  
  doc["deviceId"] = device_id;
  doc["messageType"] = "uwb_ranging";
  doc["timestamp"] = timeClient.getEpochTime();
  
  // Add UWB ranging data
  JsonObject uwb = doc.createNestedObject("uwb");
  uwb["tagId"] = UWB_DEVICE_ID;
  uwb["networkId"] = UWB_NETWORK_ID;
  
  JsonObject distances = uwb.createNestedObject("distances");
  distances["anchor1"] = latest_distance_A1;
  distances["anchor2"] = latest_distance_A2;
  distances["anchor3"] = latest_distance_A3;
  
  char payload[512];
  serializeJson(doc, payload);
  
  Serial.println("=== Sending UWB Telemetry ===");
  Serial.println(payload);
  Serial.println("=============================");
  
  mqttClient.beginMessage(topic);
  mqttClient.print(payload);
  mqttClient.endMessage();
  
  Serial.println("UWB telemetry sent to Azure IoT Hub!");
}

void setup() {
  Serial.begin(9600);
  delay(2000);
  Serial.println("Starting UWB Tag with Azure IoT Hub...");

  // Initialize UWB first
  SPI.begin();
  DW1000Ranging.initCommunication(PIN_RST, PIN_SS, PIN_IRQ);
  DW1000Ranging.attachNewRange(newRange);
  DW1000Ranging.attachNewDevice(newDevice);
  DW1000Ranging.attachInactiveDevice(inactiveDevice);
  DW1000Ranging.startAsTagCustom(UWB_DEVICE_ID, UWB_NETWORK_ID, DW1000.MODE_LONGDATA_RANGE_ACCURACY);
  
  Serial.println("UWB Tag initialized!");

  // Initialize Azure IoT Hub
  connectToWiFi();
  initializeTime();
  generateDeviceCredentials();

  String deviceKey = deriveDeviceKey(enrollment_group_key, device_registration_id);

  if (registerWithDPS(deviceKey)) {
    Serial.println("DPS registration successful!");
    generateSASToken(deviceKey);
    connectToIoTHub(deviceKey);
  } else {
    Serial.println("DPS registration failed!");
    while (true);
  }
}

void loop() {
  // Handle UWB ranging
  DW1000Ranging.loop();
  
  // Handle Azure IoT Hub
  mqttClient.poll();

  // Check if SAS token needs renewal
  if (timeClient.getEpochTime() >= (sas_token_expiry - 300)) {
    Serial.println("Renewing SAS token...");
    String deviceKey = deriveDeviceKey(enrollment_group_key, device_registration_id);
    generateSASToken(deviceKey);
    connectToIoTHub(deviceKey);
  }

  // Reconnect MQTT if disconnected
  if (!mqttClient.connected()) {
    Serial.println("MQTT disconnected, reconnecting...");
    String deviceKey = deriveDeviceKey(enrollment_group_key, device_registration_id);
    generateSASToken(deviceKey);
    connectToIoTHub(deviceKey);
  }

  // Send telemetry when we have new data and enough time has passed
  if (has_new_data && (millis() - lastMessage > messageInterval)) {
    sendUWBTelemetry();
    lastMessage = millis();
    has_new_data = false;
  }
  
  delay(100);
}
