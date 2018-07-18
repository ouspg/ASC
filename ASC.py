import json
from haralyzer import HarParser, HarPage
import re
import argparse

# Colors from here https://svn.blender.org/svnroot/bf-blender/trunk/blender/build_files/scons/tools/bcolors.py
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


'''
Dictionary for storing relevant method info
'''
method_info = {
    'path': "",
    'method': "",
    'possible_parameters': {},
    'possible_response_codes': [],
    'detected_response_codes': [],
    'count': 0,
    'count_unique_url': 0,
    'count_unique_payload': 0,
    'requests': {},
    'responses': {}
}


def read_api_spec(apispecfile):
    # Read file
    with open(apispecfile) as f:
        data = json.load(f)

    all_methods = []

    # Get endpoints
    endpoints = data["paths"].keys()

    # Parse spec info to separate method items
    for endpoint in endpoints:
        path = endpoint
        for method in data["paths"][endpoint]:
            method_info['path'] = path
            method_info['method'] = method

            response_codes = []
            #print(data["paths"][endpoint][method])
            for response_code in data["paths"][endpoint][method]["responses"]:
                response_codes.append(response_code)

            method_info['possible_response_codes'] = response_codes.copy()
            all_methods.append(method_info.copy())

    return all_methods


def print_results(result):

    # Print calculated information for every method
    for method in result:
        printcolor = bcolors.OKGREEN
        if method['count'] == 0:
            printcolor = bcolors.FAIL

        print(printcolor + method['method'].upper() + " " + method['path'] + bcolors.ENDC)

        print("USAGES: " + str(method['count']))
        print("UNIQUE URLS: " + str(method['count_unique_url']))

        if (method['method'].upper() == 'POST') or (method['method'].upper() == 'PUT'):
            print("UNIQUE POST/PUT PAYLOADS: " + str(method['count_unique_payload']))

        for defined_response_code in method['possible_response_codes']:
            if defined_response_code in method['detected_response_codes']:
                print(bcolors.OKGREEN + "RESPONSE CODE " + str(defined_response_code) + " OCCURED" + bcolors.ENDC)
            else:
                print(bcolors.FAIL + "RESPONSE CODE " + str(defined_response_code) + " NOT OCCURED" + bcolors.ENDC)

        for detected_response_code in method['detected_response_codes']:
            if detected_response_code not in method['possible_response_codes']:
                print(bcolors.FAIL + "UNDEFINED RESPONSE CODE " + str(detected_response_code) + " OCCURED" + bcolors.ENDC)

        print("")


def read_har(harfile):

    # Read harfile and return haralyzer parser
    with open(harfile, 'r') as f:
        har_parser = HarParser(json.loads(f.read()))

    return har_parser


def analyze(all_methods, har_parser):

    # Loop through methods and har file and find endpoint calls and unique urls/payloads
    for method in all_methods:
        method_path = re.sub('[{].*[}]', '[^/]*', method['path'])

        # Create unique sets
        url_unique_set = set()
        payload_unique_set = set()
        response_codes_unique_set = set()

        # Loop through HAR entries
        for page in har_parser.pages:
            for entry in page.entries:
                url = entry["request"]["url"]
                method_type = entry["request"]["method"]
                response_code = entry["response"]["status"]

                # Regexping different urls might need more testing
                if re.search(method_path + "([^/]|$|[?])", url) and (method_type.lower() == method["method"].lower()):
                    method['count'] += 1
                    url_unique_set.add(url)
                    response_codes_unique_set.add(str(response_code))

                    # Collect payloads as string
                    if (method_type.upper() == 'POST') or (method_type.upper() == 'PUT'):
                        post_string = str(json.dumps(entry["request"]["postData"]))
                        payload_unique_set.add(post_string)

        method['count_unique_url'] = len(url_unique_set)
        method['count_unique_payload'] = len(payload_unique_set)
        method['detected_response_codes'] = list(response_codes_unique_set)

    return all_methods

def main():
    parser = argparse.ArgumentParser(description='Calculate API spec coverage from HAR files and API spec')
    parser.add_argument('apispec', help='Api specification file')
    parser.add_argument('harfile', help='Captured traffic in HAR file format')

    args = parser.parse_args()

    # Read API spec
    all_methods = read_api_spec(args.apispec)

    # Read HAR file
    har_parser = read_har(args.harfile)

    # Compare API spec and HAR file
    analyze(all_methods, har_parser)

    # Print results in nice form
    print_results(all_methods)


if __name__ == "__main__":
    main()
