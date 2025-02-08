# NICLA-TrafficClassifier

NICLA-TrafficClassifier is a real‑time network traffic monitoring and classification system. The project uses a Python script on a PC to capture network traffic and extract a 19‑element feature vector (Include most important features), which is sent over a serial port to a Nicla Vision board. The Nicla board then runs an Edge Impulse classifier to determine whether the traffic is "Malicious" or "Normal" and indicates the result via an LED (green for normal, red for malicious).

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Programmer's Manual](#programmers-manual)
- [User's Manual](#users-manual)

---

## Features

- **Real-Time Traffic Capture:**  
  Uses Scapy to capture network traffic and aggregate packet features.

- **Feature Extraction:**  
  Extracts 19 key features from network packets to form a feature vector.

- **Serial Communication:**  
  Sends the feature vector from a PC to a Nicla Vision board via a serial port.

- **Edge Impulse Classification:**  
  The Nicla board classifies the feature vector as "Malicious" or "Normal" using an Edge Impulse model.

- **LED Indication:**  
  An LED is set to green for normal traffic and red for malicious traffic.

---

## Requirements

### Hardware
- A PC with Python 3.x installed.
- Nicla Vision board with an Edge Impulse model pre-loaded.
- Appropriate cables for USB/serial connectivity.

### Software
- **Python 3.x** with the following packages:
  - `scapy`
  - `pyserial`
  - others included in `requirements.txt`
- **Arduino IDE** to compile and upload the Nicla code.
- **Edge Impulse inferencing library** (e.g., `ND_Project_inferencing.h`).

---

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/NICLA-TrafficClassifier.git
   cd NICLA-TrafficClassifier
   ```

2. **Install Python Dependencies:**

   ```bash
   pip install -r requirments.txt
   ```

3. **Configure the Python Script:**
   - Open `network_capture.py` and adjust the `SERIAL_PORT` (e.g., `/dev/tty.usbmodem1101` or `COM3`) and `BAUD_RATE` to match your system.

4. **Configure the Nicla Vision Code:**
   - Open the Arduino sketch (e.g., `NICLA_TrafficClassifier.ino`) in the Arduino IDE.
   - Compile and upload the sketch to your Nicla Vision board.

---

## Programmer's Manual

### Code Structure

- **network_capture.py** (Python):
  - Uses Scapy to capture network packets.
  - Aggregates packet features into a 19‑element vector every second.
  - Sends the feature vector over a serial port.
  - Contains a thread that reads responses (classification results) from the Nicla board.

- **NICLA_TrafficClassifier.ino** (Arduino):
  - Reads incoming serial data and parses a comma‑separated feature vector.
  - Runs the Edge Impulse classifier using the received data.
  - Uses LED outputs to indicate the classification result (green for normal, red for malicious).

### Customization

- **Python Side:**
  - Change `SERIAL_PORT` and `BAUD_RATE` in `network_capture.py` to match your system.
  - Adjust `WINDOW_DURATION` if you wish to use a different time window for aggregation.
  - Modify the feature extraction logic if necessary.


### Debugging Tips

- Ensure that the serial port is not used by any other application (e.g., the Arduino Serial Monitor) when running the Python script.
- Use serial print statements in both Python and Arduino code to verify data flow.
- Confirm that the feature vector is correctly formatted (exactly 19 comma‑separated values).

---

## User's Manual

### Setup

1. **Hardware Setup:**
   - Connect the Nicla Vision board to your PC via USB.
   - Ensure your network interface is active and available for packet capture.

2. **Software Setup:**
   - Run the Python script from your PC:
     ```bash
     sudo python3 network_capture.py
     ```
     *(Use `sudo` or run as administrator if required.)*
   - Ensure that the Arduino Serial Monitor is closed so that the Python script can access the serial port.

### Operation

- **Real-Time Monitoring:**
  - The Python script continuously captures network traffic and sends feature vectors to the Nicla Vision board.
  - The Nicla board receives the data, classifies it as either "Malicious" or "Normal," and then lights an LED:
    - **Green LED** indicates "Normal" traffic.
    - **Red LED** indicates "Malicious" traffic.
  - Classification results are printed to the serial output for debugging.

### Troubleshooting

- **No LED Response:**
  - Ensure that the Nicla board is correctly receiving data (check the serial prints on the PC).
- **Serial Communication Issues:**
  - Confirm that the `SERIAL_PORT` and `BAUD_RATE` settings in `network_capture.py` match your system configuration.
  - Close any applications that might be using the serial port (e.g., Arduino Serial Monitor) before running the Python script.


