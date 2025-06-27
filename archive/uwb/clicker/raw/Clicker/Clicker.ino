/**
 * 
 * @todo
 *  - move strings to flash (less RAM consumption)
 *  - fix deprecated convertation form string to char* startAsTag
 *  - give example description
 */
#include <SPI.h>
#include "DW1000Ranging.h"

// connection pins
const uint8_t PIN_RST = 7; // reset pin
const uint8_t PIN_IRQ = 8; // irq pin
const uint8_t PIN_SS = 10; // spi select pin
const uint8_t UWB_DEVICE_ID = 10;
const uint8_t UWB_NETWORK_ID = 10;

void setup() {
  Serial.begin(9600);
  delay(1000);
  //init the configuration
  DW1000Ranging.initCommunication(PIN_RST, PIN_SS, PIN_IRQ); //Reset, CS, IRQ pin
  //define the sketch as anchor. It will be great to dynamically change the type of module
  DW1000Ranging.attachNewRange(newRange);
  DW1000Ranging.attachNewDevice(newDevice);
  DW1000Ranging.attachInactiveDevice(inactiveDevice);
  //Enable the filter to smooth the distance
  //DW1000Ranging.useRangeFilter(true);
  
  //we start the module as a tag
  DW1000Ranging.startAsTagCustom(UWB_DEVICE_ID, UWB_NETWORK_ID, DW1000.MODE_LONGDATA_RANGE_ACCURACY);
}

void loop() {
  DW1000Ranging.loop();
}

// void newRange() {
//   Serial.print("from: "); Serial.print(DW1000Ranging.getDistantDevice()->getShortAddress());
//   Serial.print("\t Range: "); Serial.print(DW1000Ranging.getDistantDevice()->getRange()); Serial.print(" m");
//   Serial.print("\t RX power: "); Serial.print(DW1000Ranging.getDistantDevice()->getRXPower()); Serial.println(" dBm");
// }

#include <algorithm> // For sort()

// Define anchor IDs
const uint16_t ANCHOR_1 = 1;
const uint16_t ANCHOR_2 = 2;
const uint16_t ANCHOR_3 = 3;

// Measurement configuration
const uint8_t MAX_MEASUREMENTS = 20;
const uint8_t OUTLIERS_TO_REMOVE = 3; // Top and bottom

// Measurement buffers for each anchor
float measurements_A1[MAX_MEASUREMENTS];
float measurements_A2[MAX_MEASUREMENTS];
float measurements_A3[MAX_MEASUREMENTS];
uint8_t measurementIndex_A1 = 0;
uint8_t measurementIndex_A2 = 0;
uint8_t measurementIndex_A3 = 0;

void processAndPrintAverage(uint16_t anchorID, float* measurements, uint8_t& index) {
    // Sort measurements
    std::sort(measurements, measurements + MAX_MEASUREMENTS);
    
    // Calculate trimmed average (skip first and last OUTLIERS_TO_REMOVE)
    float sum = 0;
    for(uint8_t i = OUTLIERS_TO_REMOVE; i < MAX_MEASUREMENTS - OUTLIERS_TO_REMOVE; i++) {
        sum += measurements[i];
    }
    
    float average = sum / (MAX_MEASUREMENTS - 2*OUTLIERS_TO_REMOVE);
    
    Serial.print("Anchor ");
    Serial.print(anchorID);
    Serial.print(" filtered average: ");
    Serial.print(average, 3); // 3 decimal places
    Serial.println(" m");
    
    // Reset index
    index = 0;
}

void newRange() {
    DW1000Device* device = DW1000Ranging.getDistantDevice();
    uint16_t anchorID = device->getShortAddress();
    float range = device->getRange();
    
    // Store measurement in appropriate buffer
    switch(anchorID) {
        case ANCHOR_1:
            measurements_A1[measurementIndex_A1++] = range;
            if(measurementIndex_A1 >= MAX_MEASUREMENTS) {
                processAndPrintAverage(ANCHOR_1, measurements_A1, measurementIndex_A1);
            }
            break;
            
        case ANCHOR_2:
            measurements_A2[measurementIndex_A2++] = range;
            if(measurementIndex_A2 >= MAX_MEASUREMENTS) {
                processAndPrintAverage(ANCHOR_2, measurements_A2, measurementIndex_A2);
            }
            break;
            
        case ANCHOR_3:
            measurements_A3[measurementIndex_A3++] = range;
            if(measurementIndex_A3 >= MAX_MEASUREMENTS) {
                processAndPrintAverage(ANCHOR_3, measurements_A3, measurementIndex_A3);
            }
            break;
            
        default:
            Serial.print("Unknown anchor: ");
            Serial.println(anchorID);
            return;
    }
    
    // Raw data print
    // Serial.print("Anchor ");
    // Serial.print(anchorID);
    // Serial.print(" raw: ");
    // Serial.print(range, 3);
    // Serial.println(" m");
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

