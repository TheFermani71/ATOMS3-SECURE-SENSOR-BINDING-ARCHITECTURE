# ATOMS3 – SECURE SENSOR BINDING ARCHITECTURE
* This firmware implements a security model
* based on:
* - Secure Boot + Flash Encryption (assumed to be active at the HW level)
* - Sensor binding to APIs
* - Encrypted data types (Int)
* - Secure and callable arithmetic APIs
* - Complete execution trace
* - Hash + ECDSA signature for remote attestation
*
* Objective:
* Prevent manipulation of sensor data(GPS + ACC + TEMP) and the
* execution flow, even in the presence of public or modifiable
* application code.
