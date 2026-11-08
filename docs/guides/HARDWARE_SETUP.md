# Hardware Setup Guide

## Bill of Materials

- TTGO T-Beam v1.1 (ESP32 + SX1276 LoRa + GPS)
- 868/915 MHz antenna (SMA)
- 18650 Li-Ion battery
- USB-C cable

The hardware costs tens of dollars: T-Beam class boards are around 30 to 40 USD.

## Assembly

1. Insert 18650 battery into T-Beam holder (observe polarity)
2. Attach SMA antenna to the LoRa port (not GPS port)
3. Connect USB-C for initial flashing

## Firmware

The firmware built today is the power-loss bench for the flash storage layer, in `targets/esp32-bench`. It is a standalone Cargo project with its own toolchain; build, commissioning and flashing steps are in [`targets/esp32-bench/README.md`](../../targets/esp32-bench/README.md). Arxia node firmware for the T-Beam is not built yet.

## Solar Operation

No node firmware runs on the board yet, so power consumption has not been measured and this guide gives no solar sizing.

## Antenna Considerations

- **Never operate without an antenna** - this can damage the SX1276
- Use a tuned antenna for your frequency band (868 MHz EU / 915 MHz US)
- Higher gain antennas improve range but narrow the radiation pattern
- For omnidirectional coverage: 3 dBi collinear antenna

## LoRa Parameters

Proposed starting values for the radio link, not final. No LoRa transport is implemented in this repository yet, so nothing applies these values today. The default path is raw LoRa.

- Bandwidth: 125 kHz
- Spreading Factor: SF7 (adjustable SF7-SF12)
- Coding Rate: 4/5
- TX Power: 14 dBm (EU limit)
