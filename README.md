# Kingpin Master Server

A lightweight master server implementation optimized for Kingpin, based on the DPMaster architecture.

## Features

* **GameSpy V1 Protocol:** Uses a lightweight, stripped-down query protocol optimized specifically for Kingpin client/server traffic.
* **Dual Engine Support:** Full tracking support for both standard Kingpin and KingpinQ3 clients.
* **Flexible Backend:** Dynamically loads active master server listings from remote HTTP web lists or local text files.

## Compilation & Installation

### 🐧 Linux (Ubuntu / Debian)

Install dependencies and compile using the provided Makefile:
```bash
sudo apt update
sudo apt install build-essential libcurl4-openssl-dev
make
```
The compiled executable will be placed in `bin/master` alongside your configuration files.

---

### 🪟 Windows (MSVC / Visual Studio)

1. Open the solution file in Visual Studio.
2. Change your active build configuration to **`Release_curl_dll`**.
3. Build the solution (`Ctrl + Shift + B`).

#### Dependencies
* **Dynamic Fallback:** If `libcurl.dll` is missing from the application folder at runtime, the master server automatically falls back to native Windows `WinHTTP` routines.
* **Manual Setup:** To use curl, download the official Windows binaries from [curl.se](https://curl.se) and copy `libcurl.dll` into your executable folder.

## License

This project links against curl. If distributing compiled binaries alongside `libcurl.dll`, ensure you include the appropriate curl license attributions in your release package.