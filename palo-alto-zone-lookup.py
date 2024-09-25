import requests
import xml.etree.ElementTree as ET
import urllib.parse
import urllib3
import logging
import datetime
import csv

# Disable SSL warnings (not recommended for production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_managed_devices(panorama_ip, api_key):
    """
    Retrieves the list of managed devices from Panorama.
    """
    url = f"https://{panorama_ip}/api/"
    params = {
        'type': 'op',
        'cmd': '<show><devices><connected></connected></devices></show>',
        'key': api_key
    }

    logging.debug(f"Managed devices request URL: {url}")
    logging.debug(f"Managed devices request params: {params}")

    response = requests.get(url, params=params, verify=False)
    logging.debug(f"Managed devices response status code: {response.status_code}")
    logging.debug(f"Managed devices response content:\n{response.text}")

    if response.status_code != 200:
        logging.error(f"Failed to retrieve managed devices: {response.text}")
        return None

    try:
        root = ET.fromstring(response.content)
        devices = root.findall(".//devices/entry")
        device_serials = [device.find('serial').text for device in devices if device.find('serial') is not None]
        logging.debug(f"Managed devices serial numbers: {device_serials}")
        return device_serials
    except ET.ParseError as e:
        logging.error(f"XML parsing error: {e}")
        return None

def get_zone_interface_mapping(firewall_ip, api_key, is_panorama=False, target_device=None):
    """
    Retrieves the zone configuration from a firewall or Panorama.
    """
    url = f"https://{firewall_ip}/api/"

    if is_panorama:
        # Use operational command to get running configuration from the device
        params = {
            'type': 'op',
            'cmd': '<show><config><running></running></config></show>',
            'key': api_key,
            'target': target_device
        }
    else:
        # XPath for individual firewall
        xpath = "/config/devices/entry/vsys/entry[@name='vsys1']/zone"
        params = {
            'type': 'config',
            'action': 'get',
            'xpath': xpath,
            'key': api_key
        }

    logging.debug(f"Zone mapping request URL: {url}")
    logging.debug(f"Zone mapping request params: {params}")

    response = requests.get(url, params=params, verify=False)
    logging.debug(f"Zone mapping response status code: {response.status_code}")
    logging.debug(f"Zone mapping response content:\n{response.text}")

    if response.status_code != 200:
        logging.error(f"Failed to retrieve zone configuration: {response.text}")
        return None

    zone_interface_mapping = {}
    try:
        root = ET.fromstring(response.content)
        if is_panorama:
            # Parse the running configuration to get zones
            zones = root.findall(".//zone/entry")
        else:
            zones = root.findall(".//entry")

        for zone in zones:
            zone_name = zone.attrib.get('name')
            members = zone.findall(".//member")
            for member in members:
                interface = member.text
                zone_interface_mapping[interface] = zone_name
        logging.debug(f"Zone interface mapping: {zone_interface_mapping}")
    except ET.ParseError as e:
        logging.error(f"XML parsing error: {e}")
        return None

    return zone_interface_mapping

def perform_fib_lookup(firewall_ip, api_key, ip_address, virtual_router, is_panorama=False, target_device=None):
    """
    Performs a FIB lookup on a firewall or a managed device via Panorama.
    """
    cmd = f'<test><routing><fib-lookup><virtual-router>{virtual_router}</virtual-router><ip>{ip_address}</ip></fib-lookup></routing></test>'
    url = f"https://{firewall_ip}/api/"
    params = {
        'type': 'op',
        'key': api_key
    }
    if is_panorama:
        params['target'] = target_device

    data = {
        'cmd': cmd
    }

    logging.debug(f"FIB lookup request URL: {url}")
    logging.debug(f"FIB lookup request params: {params}")
    logging.debug(f"FIB lookup request data: {data}")

    response = requests.post(url, params=params, data=data, verify=False)
    logging.debug(f"FIB lookup response status code: {response.status_code}")
    logging.debug(f"FIB lookup response content:\n{response.text}")

    if response.status_code != 200:
        logging.error(f"Failed to perform FIB lookup: {response.text}")
        return None

    try:
        root = ET.fromstring(response.content)
        status = root.attrib.get('status')
        if status != 'success':
            logging.error(f"FIB lookup failed for IP {ip_address} on virtual router {virtual_router}")
            logging.error(f"Response: {response.text}")
            return None

        result_element = root.find(".//result")
        if result_element is None:
            logging.warning(f"No route found for IP {ip_address} on virtual router {virtual_router}")
            return None

        # Directly extract the interface element
        interface_element = result_element.find('interface')
        if interface_element is not None:
            interface = interface_element.text.strip()
            logging.debug(f"Extracted interface: {interface}")
        else:
            logging.warning(f"No interface found in FIB lookup result for IP {ip_address} on virtual router {virtual_router}")
            return None

        result = {
            'ip_address': ip_address,
            'virtual_router': virtual_router,
            'destination_interface': interface,
        }
        return result
    except ET.ParseError as e:
        logging.error(f"XML parsing error: {e}")
        return None

def main():
    # Get current date/time for filenames
    current_datetime = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    # Set up logging with date/time in filename
    log_filename = f'api_debug_log_{current_datetime}.txt'
    logging.basicConfig(
        filename=log_filename,
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s:%(message)s'
    )

    # Prompt for inputs
    mode = input("Are you using Panorama or individual firewalls? Enter 'panorama' or 'firewalls': ").strip().lower()
    if mode == 'panorama':
        firewall_ip = input("Enter Panorama IP Address: ").strip()
        api_key = input("Enter Panorama API Key: ").strip()
        target_device = input("Enter Target Device Serial Number (or 'all' for all devices): ").strip()
        routing_ips = input("Enter Routing IP Address(es) (comma-separated): ").strip().split(',')
        virtual_routers = input("Enter Virtual Router Name(s) (comma-separated): ").strip().split(',')

        # Clean up inputs
        routing_ips = [ip.strip() for ip in routing_ips if ip.strip()]
        virtual_routers = [vr.strip() for vr in virtual_routers if vr.strip()]

        logging.info(f"Script started in Panorama mode with Panorama IP: {firewall_ip}")
        logging.info(f"Target Device Serial Number: {target_device}")
        logging.info(f"Routing IPs: {routing_ips}")
        logging.info(f"Virtual Routers: {virtual_routers}")

        if target_device.lower() == 'all':
            # Retrieve all managed devices
            device_serials = get_managed_devices(firewall_ip, api_key)
            if not device_serials:
                logging.error("Failed to retrieve managed devices, exiting script.")
                return
        else:
            device_serials = [target_device]

        all_results = []

        for device_serial in device_serials:
            logging.info(f"Processing device serial number: {device_serial}")
            # Get zone to interface mapping
            zone_interface_mapping = get_zone_interface_mapping(firewall_ip, api_key, is_panorama=True, target_device=device_serial)
            if zone_interface_mapping is None:
                logging.error(f"Zone interface mapping failed for device {device_serial}, skipping to next device.")
                continue

            # Perform FIB lookups and collect results
            results = []
            for ip_address in routing_ips:
                for virtual_router in virtual_routers:
                    fib_result = perform_fib_lookup(firewall_ip, api_key, ip_address, virtual_router, is_panorama=True, target_device=device_serial)
                    if fib_result:
                        interface = fib_result['destination_interface']
                        zone = zone_interface_mapping.get(interface, 'Unknown')
                        fib_result['destination_zone'] = zone
                        fib_result['device_serial'] = device_serial
                        results.append(fib_result)
                    else:
                        logging.warning(f"No FIB result for IP {ip_address} on virtual router {virtual_router} for device {device_serial}")

            all_results.extend(results)

        # Output results
        print("\nResults:")
        print("{:<15} {:<15} {:<15} {:<20} {:<15}".format('Device Serial', 'IP Address', 'Virtual Router', 'Destination Interface', 'Destination Zone'))
        for result in all_results:
            print("{:<15} {:<15} {:<15} {:<20} {:<15}".format(
                result['device_serial'],
                result['ip_address'],
                result['virtual_router'],
                result['destination_interface'],
                result['destination_zone']
            ))

        # Write results to CSV file
        csv_filename = f'output_{current_datetime}.csv'
        with open(csv_filename, mode='w', newline='') as csv_file:
            fieldnames = ['Device Serial', 'IP Address', 'Virtual Router', 'Destination Interface', 'Destination Zone']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for result in all_results:
                writer.writerow({
                    'Device Serial': result['device_serial'],
                    'IP Address': result['ip_address'],
                    'Virtual Router': result['virtual_router'],
                    'Destination Interface': result['destination_interface'],
                    'Destination Zone': result['destination_zone']
                })
        print(f"\nResults have been saved to {csv_filename}")
        logging.info("Script completed.")

    elif mode == 'firewalls':
        num_firewalls = int(input("How many firewalls do you want to process? ").strip())
        firewalls = []
        for i in range(num_firewalls):
            print(f"\nFirewall {i+1}:")
            fw_ip = input(f"Enter Firewall {i+1} IP Address: ").strip()
            fw_api_key = input(f"Enter Firewall {i+1} API Key: ").strip()
            firewalls.append({'ip': fw_ip, 'api_key': fw_api_key})

        routing_ips = input("Enter Routing IP Address(es) (comma-separated): ").strip().split(',')
        virtual_routers = input("Enter Virtual Router Name(s) (comma-separated): ").strip().split(',')

        # Clean up inputs
        routing_ips = [ip.strip() for ip in routing_ips if ip.strip()]
        virtual_routers = [vr.strip() for vr in virtual_routers if vr.strip()]

        logging.info(f"Script started in Firewalls mode with {num_firewalls} firewalls.")
        logging.info(f"Routing IPs: {routing_ips}")
        logging.info(f"Virtual Routers: {virtual_routers}")

        all_results = []

        for fw in firewalls:
            logging.info(f"Processing Firewall IP: {fw['ip']}")
            # Get zone to interface mapping for each firewall
            zone_interface_mapping = get_zone_interface_mapping(fw['ip'], fw['api_key'])
            if zone_interface_mapping is None:
                logging.error(f"Zone interface mapping failed for firewall {fw['ip']}, skipping to next firewall.")
                continue

            # Perform FIB lookups and collect results
            results = []
            for ip_address in routing_ips:
                for virtual_router in virtual_routers:
                    fib_result = perform_fib_lookup(fw['ip'], fw['api_key'], ip_address, virtual_router)
                    if fib_result:
                        interface = fib_result['destination_interface']
                        zone = zone_interface_mapping.get(interface, 'Unknown')
                        fib_result['destination_zone'] = zone
                        fib_result['firewall_ip'] = fw['ip']
                        results.append(fib_result)
                    else:
                        logging.warning(f"No FIB result for IP {ip_address} on virtual router {virtual_router} for firewall {fw['ip']}")

            all_results.extend(results)

        # Output results
        print("\nResults:")
        print("{:<15} {:<15} {:<15} {:<20} {:<15}".format('Firewall IP', 'IP Address', 'Virtual Router', 'Destination Interface', 'Destination Zone'))
        for result in all_results:
            print("{:<15} {:<15} {:<15} {:<20} {:<15}".format(
                result['firewall_ip'],
                result['ip_address'],
                result['virtual_router'],
                result['destination_interface'],
                result['destination_zone']
            ))

        # Write results to CSV file
        csv_filename = f'output_{current_datetime}.csv'
        with open(csv_filename, mode='w', newline='') as csv_file:
            fieldnames = ['Firewall IP', 'IP Address', 'Virtual Router', 'Destination Interface', 'Destination Zone']
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for result in all_results:
                writer.writerow({
                    'Firewall IP': result['firewall_ip'],
                    'IP Address': result['ip_address'],
                    'Virtual Router': result['virtual_router'],
                    'Destination Interface': result['destination_interface'],
                    'Destination Zone': result['destination_zone']
                })
        print(f"\nResults have been saved to {csv_filename}")
        logging.info("Script completed.")

    else:
        print("Invalid input. Please enter 'panorama' or 'firewalls'.")

if __name__ == "__main__":
    main()
