import json
from haralyzer import HarParser, HarPage
import re
import argparse
import copy
from jsonschema import validate
from jsonschema import validators

from prance import ResolvingParser

# Colors from here https://svn.blender.org/svnroot/bf-blender/trunk/blender/build_files/scons/tools/bcolors.py


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


class Endpoint:
    def __init__(self, path, methods):
        self.path = path
        self.methods = methods

    def inputLogEntry(self, entry):
        # Input entry under correct method
        method_type = entry['request']['method'].lower()
        self.methods[method_type].addEntry(entry)

    def outputAnalysis(self):
        # Print analysis
        for mtd in self.methods.keys():
            print(bcolors.HEADER + f"Endpoint {self.path} - method {mtd}" + bcolors.ENDC)
            self.methods[mtd].printAnalysis()
            print('')
            print('')

    def analyzeAll(self):
        for mtd in self.methods.keys():
            self.methods[mtd].analyze()


# Class for single method
class SingleMethod:
    def __init__(self, type, path, methodinfo):
        self.type = type
        self.path = path
        self.response_schemas = ""
        self.parameters = ""
        self.methodinfo = methodinfo

        # Array of entries
        self.logs = []

        self.analysis_result = ""

    def addEntry(self, entry):
        # Add single entry to list
        self.logs.append(entry)

    def analyze(self):
        # Make endpoint method analysis with all entries

        # Dict to store analysis results
        analysis = {
            'method': self.type,
            'operationId': "",
            'request_info': "",
            'responses_info': "",
            'anomaly_entries': [],
            'total_count': 0
        }

        # Get total count
        analysis['total_count'] = len(self.logs)

        analysis_requests = self.methodinfo['parameters']

        for param in analysis_requests:

            param['analysis'] = {
                'values': [],
                'count': 0
            }

        analysis_responses = {
            'responses': self.methodinfo['responses']
        }

        for response in analysis_responses['responses']:
            analysis_responses['responses'][response].update({'analysis': {
                'values': [],
                'count': 0
            }})

        # Run analysis for every log entry for this endpoint method
        for entry in self.logs:
            url = entry['request']['url']

            for param in analysis_requests:
                # TODO: Works only with one path parameter
                if param['in'] == 'path':
                    if '{' in self.path and '}' in self.path:
                        # Seek parameter value and handle it default way
                        prepart = self.path.split('{' + param['name'] + '}')[0]
                        paramvalue = re.search(prepart + '(.*)([^/]|$|[?])', url).group(1)

                        param['analysis']['values'].append(paramvalue)
                        param['analysis']['count'] += 1

                    # TODO: Make anomaly entry if parameter not found

                elif param['in'] == 'query':
                    # Check query parameters as default way
                    parameter_found = False

                    for queryparameter in entry['request']['queryString']:
                        if queryparameter['name'] == param['name']:
                            paramvalue = queryparameter['value']
                            param['analysis']['values'].append(paramvalue)
                            param['analysis']['count'] += 1
                            parameter_found = True

                    # Add anomaly if required parameter does not exist

                    if param['required'] and not parameter_found:
                        # Anomaly because of required parameter is not found
                        anomaly = {
                            "entry": entry,
                            "reason": "Required parameter " + str(
                                param['name']) + " was not found in request query parameters"
                        }

                        analysis['anomaly_entries'].append(anomaly)

                elif param['in'] == 'header':
                    # Check request header parameters as default way
                    parameter_found = False

                    for headerparameter in entry['request']['headers']:
                        if headerparameter['name'] == param['name']:
                            paramvalue = headerparameter['value']
                            param['analysis']['values'].append(paramvalue)
                            param['analysis']['count'] += 1

                    # Add anomaly because request header parameter is not found
                    if param['required'] and not parameter_found:
                        # Anomaly because of required parameter is not found
                        anomaly = {
                            "entry": entry,
                            "reason": "Required parameter " + str(
                                param['name']) + " was not found in request header parameters"
                        }

                        analysis['anomaly_entries'].append(anomaly)

                elif param['in'] == 'body':
                    # Checks body content of request
                    # Validates request body with given schema by json schema validator
                    # Checks if request body json is broken

                    paramvalue = entry['request']['postData']['text']
                    param['analysis']['values'].append(paramvalue)
                    param['analysis']['count'] += 1

                    # TODO: Possibly new feature to check and handle single schema fields as parameters if needed

                    try:
                        ins = json.loads(paramvalue)
                    except:
                        # Notify
                        print("Cannot parse request parameters")

                        # Add anomaly
                        anomaly = {
                            "entry": entry,
                            "reason": "Could not parse sended data object in body to json object"
                        }

                        analysis['anomaly_entries'].append(anomaly)

                    else:
                        try:
                            sch = json.loads(json.dumps(param['schema']))

                            validate(instance=ins, schema=sch, cls=validators.Draft4Validator)
                        except:
                            # Add entry to anomalities
                            anomaly = {
                                "entry": entry,
                                "reason": "Validator produced error when validating this request body"
                            }

                            analysis['anomaly_entries'].append(anomaly)

                    pass
                elif param['in'] == 'formData':
                    # Form data parameters can be found either params field or content field in HAR
                    # Parsing and analyzing data from there
                    if 'params' in entry['request']['postData']:
                        for formparam in entry['request']['postData']['params']:
                            if formparam['name'] == param['name']:
                                paramvalue = formparam['value']
                                param['analysis']['values'].append(paramvalue)
                                param['analysis']['count'] += 1

                            # TODO: Detect if parameter has some anomality or not corresponding API spec

                    elif 'text' in entry['request']['postData']:
                        # Parse multipart data from response with custom functions
                        bound = get_multipart_boundary(entry['request'])
                        parseddata = decode_multipart(str(entry['request']['postData']['text']), bound)

                        for p_name, p_value in parseddata:
                            if p_name == param['name']:
                                param['analysis']['values'].append(p_value)
                                param['analysis']['count'] += 1

                            # TODO: Detect if parameter has some anomality or not corresponding API spec

            # Analyzing responses
            response_code = str(entry['response']['status'])

            if response_code in analysis_responses['responses'].keys():
                analysis_responses['responses'][response_code]['analysis']['count'] += 1
                analysis_responses['responses'][response_code]['analysis']['values'].append(entry['response']['content']['text'])

                # TODO: Determine what to do with xml bodies, maybe auto detect and use XML validator
                # Now xml bodies are just skipped

                # If response has schema specified, compare response body content with it
                if 'schema' in analysis_responses['responses'][response_code]:
                    sch = json.loads(json.dumps(analysis_responses['responses'][response_code]['schema']))

                    # Try parse and validate
                    try:
                        ins = json.loads(entry['response']['content']['text'])
                        validate(instance=ins, schema=sch, cls=validators.Draft4Validator)
                    except Exception as e:
                        print(str(e))
                        # TODO: Make exception add anomaly

            else:
                # Undefined response code detected
                # Decide if default response is present and make anomaly text based on it
                anomaly = {
                    "entry": entry,
                    "reason": "Response code " + str(response_code) + " is not explictly defined in API specification"
                }

                if 'default' in analysis_responses['responses'].keys():
                    anomaly['reason'] += ". NOTICE: Specification has default response specified"

                analysis['anomaly_entries'].append(anomaly)

        analysis['request_info'] = analysis_requests
        analysis['responses_info'] = analysis_responses

        self.analysis_result = analysis

    def printAnalysis(self):
        # Just prints analysis fancy way
        if self.analysis_result['total_count'] == 0:
            print("\t" + bcolors.FAIL + f"Total number of request/responses: {self.analysis_result['total_count']}" + bcolors.ENDC)
            return
        else:
            print("\t" + bcolors.OKGREEN +f"Total number of request/responses: {self.analysis_result['total_count']}" + bcolors.ENDC)

        print('')
        print("Parameters occurred in requests:")

        for param in self.analysis_result['request_info']:
            param_occurrence_count = param['analysis']["count"]

            # Does not preserve order
            param_occurrence_count_unique = len(list(set(param['analysis']["values"])))

            if param_occurrence_count == 0:
                print("\t" + bcolors.FAIL + f"Parameter named {param['name']} never occurred" + bcolors.ENDC)
            else:
                print("\t" + bcolors.OKGREEN + f"Parameter named {param['name']}  occurred {param_occurrence_count} time(s)" + bcolors.ENDC)
                print("\t" + "\t" + f"Unique valued occurrences: {param_occurrence_count_unique}")

        print('')
        print("Responses occurred:")

        for response_code, content in self.analysis_result['responses_info']['responses'].items():

            if response_code == 'default':
                break

            response_occurrence_count = content['analysis']['count']
            response_occurrence_count_unique = len(list(set(content['analysis']['values'])))

            print("\t" + f"Response code {response_code}")

            if response_occurrence_count > 0:
                print("\t" + bcolors.OKGREEN + f"Total occurrences: {response_occurrence_count}" + bcolors.ENDC)
                print("\t" + "\t" + f"Unique valued response content occurrences: {response_occurrence_count_unique}")
            else:
                print("\t" + bcolors.FAIL + f"Total occurrences: {response_occurrence_count}" + bcolors.ENDC)

            print('')

        print('')
        if len(self.analysis_result['anomaly_entries']) > 0:
            print(f"Anomaly entries in traffic: {len(self.analysis_result['anomaly_entries'])}")
            for anomaly_entry in self.analysis_result['anomaly_entries']:

                print("\t" + f"Anomaly description: {anomaly_entry['reason']}")
                print("\t" + f"Anomalic request entry in HAR file: {anomaly_entry['entry']}")


class Schema:
    '''
    Not yet used anywhere
    '''
    def __init__(self):
        self.payload = ""


class Parameter:
    '''
    Not yet used anywhere
    '''
    def __init__(self):
        self.name = ""
        self.location = "" #Possibly enum?
        self.required = "" #Boolean
        self.schema = "" #Schema json

class ASC:
    def __init__(self, apispec_addr, har_addr):
        self.apispec_addr = apispec_addr
        self.har_addr = har_addr

        self.apispec = ""
        self.harobject = ""

        self.options = ""

        self.endpoints = {}
        self.basepath = ""

    def makeharparser(self):
        # Initialize har parser object
        with open(self.har_addr , 'r') as f:
            self.harobject = HarParser(json.loads(f.read()))

    def getapispec(self):
        # Might be futile as prance parser already uses URL to get spec
        pass

    def parseapispec(self):
        # Parse API spec to endpoint and method objects with prance parser
        specparser = ResolvingParser(self.apispec_addr)

        self.apispec = specparser.specification
        paths = specparser.specification['paths']

        for endpoint in paths.keys():
            mthds = {}
            for method in paths[endpoint].keys():
                minfo = copy.deepcopy(paths[endpoint][method])
                mthds[method] = SingleMethod(method, endpoint, minfo)
            self.endpoints[endpoint] = (Endpoint(endpoint, mthds))

    def preparsehar(self):
        # Parse har file entries to correct endpoints to wait for analysis
        for page in self.harobject.pages:
            for entry in page.entries:
                url = entry['request']['url']

                # TODO: Does not work with 2 path parameters
                for path in self.endpoints.keys():
                    if '{' in path and '}' in path:
                        prepart = path.split('{')[0]
                        afterpart = path.split('}')[1]

                        # TODO: Might mess with query parameters
                        if re.search(prepart, url):
                            if (len(afterpart) > 0) and (url.endswith(afterpart)):
                                self.endpoints[path].inputLogEntry(entry)
                                break

                            elif len(afterpart) == 0:
                                urlafterpart = url.split(prepart)[1]
                                if '/' not in urlafterpart:
                                    self.endpoints[path].inputLogEntry(entry)
                                    break

                    else:
                        # TODO: Check if works with same time with query and path parameters
                        urltotest = url.split("?")[0]

                        if urltotest.endswith(path) or urltotest.endswith(path + '/'):
                            self.endpoints[path].inputLogEntry(entry)
                            break

    def analyze(self):
        # Trigger every endppoint analysis
        for endpoint in self.endpoints.keys():
            self.endpoints[endpoint].analyzeAll()

    def exportresults(self):
        # Export results to command line
        for endpoint in self.endpoints.keys():
            self.endpoints[endpoint].outputAnalysis()


def main():
    parser = argparse.ArgumentParser(description='Calculate API spec coverage from HAR files and API spec')
    parser.add_argument('apispec', help='Api specification file')
    parser.add_argument('harfile', help='Captured traffic in HAR file format')

    args = parser.parse_args()

    asc = ASC(args.apispec, args.harfile)

    asc.parseapispec()
    asc.makeharparser()
    asc.preparsehar()
    asc.analyze()
    asc.exportresults()

def get_multipart_boundary(req_entry):

    for header in req_entry['headers']:
        if header['name'] == 'content-type':
            boundarysearch = re.search('boundary=(.*?)( |$)', header['value'])
            boundvalue = boundarysearch.group(1)
            return boundvalue


def decode_multipart(text, boundary):
    # Returns array of tuple name-value pairs
    splitted_text = text.split(boundary)

    actual_items = []

    for item in splitted_text:
        if item == '--' or item == '--\r\n':
            continue
        actual_items.append(item)

    parsed_items = []

    for a_item in actual_items:
        namesearch = re.search('name="(.*?)"', a_item)

        namevalue = namesearch.group(1)

        valuesearch = re.search('\r\n\r\n([\s\S]*)\r\n', a_item)

        valuevalue = valuesearch.group(1)

        parsed_items.append((namevalue, valuevalue))

    return  parsed_items

if __name__ == '__main__':
    main()