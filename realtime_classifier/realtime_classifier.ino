#include <ND_Project_inferencing.h>

#include <Arduino.h>
#include <Wire.h>
#include <stdlib.h>
#include <string.h>

#define FEATURE_COUNT 19



char inputBuffer[128];  // Buffer for incoming serial data
float features[FEATURE_COUNT];  // Array to store the feature vector

const char* EI_CLASSIFIER_LABELS[] = {
  "Malicious",
  "Normal"
};
#define EI_CLASSIFIER_LABEL_COUNT (sizeof(EI_CLASSIFIER_LABELS) / sizeof(EI_CLASSIFIER_LABELS[0]))

// This function is called by the classifier to retrieve feature data
int get_array_data(size_t offset, size_t length, float *out_ptr) {
    if (offset + length > FEATURE_COUNT) {
        return -1; // Out-of-bound request.
    }
    memcpy(out_ptr, &features[offset], length * sizeof(float));
    return 0;
}

void setup() {
    // Initialize the Serial Monitor (for debugging/receiving feature vectors)
    Serial.begin(9600);
    delay(1000);
    // Initialize Serial1 for classifier data (if using separate serial for modem, etc.)
    Serial1.begin(19200);
    delay(1000);

    // Initialize LED pins.
    pinMode(LED_BUILTIN, OUTPUT);
    
    digitalWrite(LEDG, HIGH); // Green OFF
    digitalWrite(LEDB, HIGH); // Blue OFF
    digitalWrite(LEDR, HIGH); // Red OFF

    Serial.println("NICLA Edge Impulse Classifier Ready.");
}

void loop() {
    // Check if a complete line is available from Serial
    if (Serial.available()) {
        int len = Serial.readBytesUntil('\n', inputBuffer, sizeof(inputBuffer) - 1);
        inputBuffer[len] = '\0';  // Terminate the string

        // Parse the comma-separated string into the features array.
        char *token = strtok(inputBuffer, ",");
        int index = 0;
        while (token != NULL && index < FEATURE_COUNT) {
            features[index] = atof(token);
            token = strtok(NULL, ",");
            index++;
        }
        // Only classify if we received exactly 19 values.
        if (index == FEATURE_COUNT) {
            classifySample();
        }
    }
}

void classifySample() {
    Serial.println("Running classification...");

    // Wrap features in a signal_t structure for Edge Impulse.
    ei::signal_t signal;
    signal.total_length = FEATURE_COUNT;
    signal.get_data = &get_array_data;

    // Prepare the inference result structure.
    ei_impulse_result_t result = { 0 };

    // Run the classifier (verbose mode disabled)
    EI_IMPULSE_ERROR err = run_classifier(&signal, &result, false);
    if (err != EI_IMPULSE_OK) {
        Serial.print("Error running classifier: ");
        Serial.println(err);
        return;
    }
    
    // Print the classification results.
    Serial.println("Classification Results:");
    for (size_t i = 0; i < EI_CLASSIFIER_LABEL_COUNT; i++) {
        Serial.print(EI_CLASSIFIER_LABELS[i]);
        Serial.print(": ");
        Serial.print(result.classification[i].value * 100, 2);
        Serial.println("%");
    }

    // Determine the outcome: assume index 0 is "Malicious" and index 1 is "Normal".
    float malicious_score = result.classification[0].value;
    float normal_score = result.classification[1].value;
    
    // Set the LED based on the classification result.
    if (normal_score > malicious_score) {
        // Traffic is normal: turn on the green LED and turn off the red LED.
        // Turn the LED green
        digitalWrite(LEDG, LOW); // Green ON
        digitalWrite(LEDB, HIGH); // Blue OFF
        digitalWrite(LEDR, HIGH); // Red OFF
    } else {
        // Traffic is malicious: turn on the red LED and turn off the green LED.
        // Turn the LED red
        digitalWrite(LEDG, HIGH); // Green OFF
        digitalWrite(LEDB, LOW); // Blue ON
        digitalWrite(LEDR, HIGH); // Red OFF
    }
}
