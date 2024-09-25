# Palo Alto Networks Zone and Interface Mapping with FIB Lookup

## Overview
This Python script automates the process of determining the egress interfaces and associated zones for specified IP addresses across Palo Alto Networks firewalls. It interacts with either individual firewalls or a Panorama management system, providing flexibility for various network environments. By performing Forwarding Information Base (FIB) lookups and mapping interfaces to zones, the script aids in network analysis, troubleshooting, and documentation.

## Key Features
* **Mode Selection:**
  - `Panorama Mode:` Interacts with a Panorama management system to process one or multiple managed devices. Supports targeting a specific device by serial number or all connected devices.
  - `Firewalls Mode:` Connects directly to one or multiple individual firewalls.

- **FIB Lookup:** Performs FIB lookups to determine the egress interface for specified IP addresses and virtual routers.
Supports multiple IP addresses and virtual routers in a single run.
- **Zone Interface Mapping:** Retrieves zone-to-interface mappings from firewalls or managed devices.
Accurately maps the destination interface obtained from the FIB lookup to its corresponding zone.
- **Multiple Device Support:** Processes multiple firewalls or devices, either specified individually or all devices connected to Panorama. Allows for comprehensive analysis across the network infrastructure.
- **Dynamic Logging:** Generates detailed log files with date and time stamps in the filenames.
Logs include debug information for API requests and responses, aiding in troubleshooting.
- **CSV Output:** Saves results to a CSV file with a date and time stamp in the filename.Facilitates easy sharing and archival of results.
- **User-Friendly Interaction:** Command-line interface prompts for necessary inputs. Input validation ensures correct data entry.

## How the Script Works
- **Initialization:** Imports required modules, including requests, xml.etree.ElementTree for XML parsing, urllib3 for handling HTTPS connections, logging for logging activities, datetime for timestamping, and csv for outputting results. SSL warnings are suppressed for simplicity.
- **Mode Selection and Input Collection:** Prompts the user to select between 'panorama' and 'firewalls' modes.
- **Collects necessary inputs based on the selected mode:**
  - Panorama Mode:
    -  Panorama IP address and API key.
    -  Target device serial number or 'all' to process all devices.
  - Firewalls Mode:
    -  Number of firewalls to process.
    -  For each firewall: IP address and API key.
    -  Collects routing IP addresses and virtual router names for both modes.

## Logging Configuration:

- Sets up logging with a filename that includes the current date and time.
- Logs important events and debug information.
- Processing Devices or Firewalls:
    - Panorama Mode:
      - If 'all' is selected, retrieves all managed device serial numbers from Panorama.
      - Iterates over each device serial number to perform operations.
    - Firewalls Mode:
      - Iterates over each firewall provided.

## Zone Interface Mapping Retrieval:

  - Panorama Mode:
    - Retrieves the running configuration of each target device via an operational command through Panorama.
    - Parses the running configuration to extract zone-to-interface mappings.
  - Firewalls Mode:
    - Directly retrieves zone configurations from each firewall using an XPath query.
    - Stores mappings in a dictionary for later use.

## Performing FIB Lookups:

  - For each IP address and virtual router combination, performs a FIB lookup on the device or firewall.
  - Retrieves the egress interface for the specified IP address.

## Compiling Results:

-  Maps the egress interface to the corresponding zone using the zone interface mapping.
-  Collects all relevant data, including IP address, virtual router, destination interface, and destination zone.

## Output Generation:

-  Displays the results in a formatted table on the console.
-  Writes the results to a CSV file with a date and time stamp in the filename.
-  Logs the completion of the script.

##  Usage Instructions
-  Prerequisites
    -  Python 3.x installed on the machine.
-  Required Python Libraries:
    -  `bash`
-  Copy code
    -  `pip install requests`
-  Script Execution
-  Save the Script:
    -  Save the script to a file, e.g., paloalto_zone_lookup.py.
-  Run the Script:
    -  Open a command prompt or terminal and navigate to the directory containing the script.
    -  Execute the script
    -  python paloalto_zone_lookup.py
    -  Provide Inputs

-  Viewing and Saving Results
    -  The script outputs the results to the console in a tabular format.
    -  Results are saved to a CSV file with a timestamped filename, e.g., output_20231005_153045.csv.
    -  Log files are generated with detailed debug information, e.g., api_debug_log_20231005_153045.txt.
