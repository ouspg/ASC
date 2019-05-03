import json
from haralyzer import HarParser, HarPage
import re
import argparse
import copy
from jsonschema import validate
from jsonschema import validators

from urllib.parse import urlparse

from enum import Enum

from time import time

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

    def input_log_entry(self, entry):
        # Input entry under correct method
        method_type = entry['request']['method'].lower()
        self.methods[method_type].add_entry(entry)

    def match_url_to_path(self, url):
        '''
        Just determines if url matches this endpoints path
        :param url:
        :param basepath:
        :return boolean:
        '''

        url_parsed = urlparse(url)
        # TODO: do some testing to ensure working with 2 or more path parameters

        # Is there some other smarter way to test path params than just looking for brackets?
        if '{' in self.path and '}' in self.path:
            # Create search pattern by replacing path parameter with 'anything-but-slash' wildcard
            search_pattern = re.sub('{.+}', '[^/]+', self.path) + "$"

            #print(search_pattern)
            #print(url_parsed.path)

            # Check if path matches to url
            if re.search(search_pattern, url_parsed.path):
                #print("FOUND________________")
                return True

            pass

        else:
            # No path parameters
            # TODO: Check if urllib may produce trailing slash to end of path
            if url_parsed.path.endswith(self.path):
                return True

        # No match found
        return False

    def print_endpoint_analysis_to_console(self):
        # Print analysis
        for mtd in self.methods.keys():
            print(bcolors.HEADER + f"Endpoint {self.path} - method {mtd}" + bcolors.ENDC)
            self.methods[mtd].print_method_analysis_to_console()
            print('')
            print('')

    def analyze_endpoint(self):
        for mtd in self.methods.keys():
            self.methods[mtd].analyze()

    def get_methods_not_used(self):
        # Simply returns array of methods existing but not used (GET POST etc)
        methods_not_used = []
        for mtd in self.methods.keys():
            if not self.methods[mtd].is_used():
                methods_not_used.append(mtd)

        return methods_not_used

    def is_used(self):
        # Simply true or false depending that if there is even single usage of this endpoint
        for mtd in self.methods.keys():
            if self.methods[mtd].is_used():
                return True

        return False


# Class for single method
class SingleMethod:
    def __init__(self, type, path, methodinfo, parameters):
        self.type = type # type or method?
        self.path = path
        self.response_schemas = "" #will this be futile?
        self.parameters = parameters # array of parameter objects
        self.methodinfo = methodinfo

        # Array of entries
        self.logs = []

        self.analysis_result = ""

    def add_entry(self, entry):
        # Add single entry to list
        self.logs.append(entry)

    def is_used(self):
        # returns true or false depending on count
        if len(self.logs) > 0:
            return True
        else:
            return False

    def get_responses_not_used(self):
        # return array of responses not used
        # returns as list, receiver checks if empty
        # how to handle default response stuff?
        response_not_used = []
        for response in self.analysis_result["responses_info"]['responses'].keys():
            if self.analysis_result["responses_info"]['responses'][response]['analysis']['count'] == 0:
                response_not_used.append(response)
        return response_not_used

    def analyze(self):
        # Run analysis for this method and store all analysis for later inspections

        # TODO: Looks like operationid is not used, might be needed better structures and everything here too
        analysis = {
            'method': self.type,
            'operationId': "",
            'request_info': "",
            'request_info_requestbody': "",
            'responses_info': "",
            'anomaly_entries': [],
            'total_count': 0
        }

        # Get total count
        analysis['total_count'] = len(self.logs)

        analysis_requestbody = None

        #print(self.methodinfo)
        if 'parameters' in self.methodinfo.keys():
            analysis_requests = self.methodinfo['parameters']
            print(analysis_requests)
        else:
            #looking for requestbody
            #set up termporary empty parameters

            analysis_requests = []
            #analysis_requestbodies = []
            if 'requestBody' in self.methodinfo.keys():
                analysis_requestbody = self.methodinfo['requestBody']
                analysis_requestbody['analysis'] = {
                    'values': [],
                    'count': 0
                }
            # for v3


        # Should be working with api spec 3 too now

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

            for param in self.parameters:

                # TODO: Should be usable with multiple path params now, but needs testing

                # TODO: How should lack of required parameter treated? It can be intentional in test and should not crash anything?
                if param.location == 'path':
                #if param['in'] == 'path':
                    # turha if lause?
                    #if '{' in self.path and '}' in self.path:


                    path_prepart = self.path.split('{' + param.name + '}')[0]

                    # Replace path parameters in prepath with no-slash wildcard

                    path_prepart = re.sub('{.+}', '[^/]+', path_prepart)

                    # may not work, is last match needed?
                    #paramvalue = re.search(path_prepart + '(.*)([^/]|$|[?])', url).group(0)
                    paramvalue = re.search(path_prepart + '(?P<path_parameter_value>(.*)([^/]|$|[?]))', url).group('path_parameter_value')


                    print(paramvalue)


                    # Seek parameter value and handle it default way
                    #prepart = self.path.split('{' + param['name'] + '}')[0]

                    #old ones
                    #prepart = self.path.split('{' + param.name + '}')[0]
                    #paramvalue = re.search(prepart + '(.*)([^/]|$|[?])', url).group(1)

                    #param['analysis']['values'].append(paramvalue)
                    #param['analysis']['count'] += 1
                    param.addUsage(paramvalue)

                    # TODO: Make anomaly entry if parameter not found

                #elif param['in'] == 'query':
                elif param.location == 'query':
                    # Check query parameters as default way
                    # Is query params always required?
                    parameter_found = False

                    for queryparameter in entry['request']['queryString']:
                        #if queryparameter['name'] == param['name']:
                        if queryparameter['name'] == param.name:
                            paramvalue = queryparameter['value']
                            #param['analysis']['values'].append(paramvalue)
                            #param['analysis']['count'] += 1
                            param.addUsage(paramvalue)
                            parameter_found = True

                    # Add anomaly if required parameter does not exist

                    #if param['required'] and not parameter_found:
                    if param.required and not parameter_found:
                        # Anomaly because of required parameter is not found
                        anomaly = {
                            "entry": entry,
                            "reason": "Required parameter " + str(
                                param['name']) + " was not found in request query parameters"
                        }

                        analysis['anomaly_entries'].append(anomaly)

                #elif param['in'] == 'header':
                elif param.location == 'header':
                    # Check request header parameters as default way
                    parameter_found = False

                    for headerparameter in entry['request']['headers']:
                        #if headerparameter['name'] == param['name']:
                        if headerparameter['name'] == param.name:
                            paramvalue = headerparameter['value']
                            #param['analysis']['values'].append(paramvalue)
                            #param['analysis']['count'] += 1
                            param.addUsage(paramvalue)

                    # Add anomaly because request header parameter is not found
                    #if param['required'] and not parameter_found:
                    if param.required and not parameter_found:
                        # Anomaly because of required parameter is not found
                        anomaly = {
                            "entry": entry,
                            "reason": "Required parameter " + str(
                                param['name']) + " was not found in request header parameters"
                        }

                        analysis['anomaly_entries'].append(anomaly)

                #elif param['in'] == 'body':
                elif param.location == 'body':
                    # Checks body content of request
                    # Validates request body with given schema by json schema validator
                    # Checks if request body json is broken

                    paramvalue = entry['request']['postData']['text']
                    #param['analysis']['values'].append(paramvalue)
                    #param['analysis']['count'] += 1
                    param.addUsage(paramvalue)

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
                #elif param['in'] == 'formData':
                elif param.location == 'formData':
                    # Form data parameters can be found either params field or content field in HAR
                    # Parsing and analyzing data from there
                    if 'params' in entry['request']['postData']:
                        for formparam in entry['request']['postData']['params']:
                            #if formparam['name'] == param['name']:
                            if formparam['name'] == param.name:
                                paramvalue = formparam['value']
                                #param['analysis']['values'].append(paramvalue)
                                #param['analysis']['count'] += 1
                                param.addUsage(paramvalue)

                            # TODO: Detect if parameter has some anomality or not corresponding API spec

                    elif 'text' in entry['request']['postData']:
                        # Parse multipart data from response with custom functions
                        bound = get_multipart_boundary(entry['request'])
                        parseddata = decode_multipart(str(entry['request']['postData']['text']), bound)

                        for p_name, paramvalue in parseddata:
                            #if p_name == param['name']:
                            if p_name == param.name:
                                #param['analysis']['values'].append(paramvalue)
                                #param['analysis']['count'] += 1
                                param.addUsage(paramvalue)

                            # TODO: Detect if parameter has some anomality or not corresponding API spec

            # Analyze entry from the viewpoint of requestbodyparameter (OA v3) if it exists
            if analysis_requestbody != None:
                #flow
                #check if postdata have params or text field (same as upper formData stuff)
                #just get uniqueness and validate schema, no more for now
                #should it just add more params to the list aka parse schema and just make new set of params
                if 'params' in entry['request']['postData']:
                    # Is this futile?
                    print("params values")
                    print(entry['request']['postData']['params'])
                elif 'text' in entry['request']['postData']:
                    print("text values")
                    print(entry['request']['postData']['text'])
                    # tehdään eka oletuksella että text valueissa on asiat
                    body = entry['request']['postData']['text']
                    analysis_requestbody['analysis']['values'].append(body)
                    analysis_requestbody['analysis']['count'] += 1


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

    def print_method_analysis_to_console(self):
        # Just prints analysis fancy way
        if self.analysis_result['total_count'] == 0:
            print("\t" + bcolors.FAIL + f"Total number of request/responses: {self.analysis_result['total_count']}" + bcolors.ENDC)
            return
        else:
            print("\t" + bcolors.OKGREEN +f"Total number of request/responses: {self.analysis_result['total_count']}" + bcolors.ENDC)

        print('')
        print("Parameters occurred in requests:")


        # Rewriting params analysis code because of new class
        #for param in self.analysis_result['request_info']:
        for param in self.parameters:
            #param_occurrence_count = param['analysis']["count"]

            # Does not preserve order
            #param_occurrence_count_unique = len(list(set(param['analysis']["values"])))
            param_occurrence_count_unique = len(param.unique_values)

            #if param_occurrence_count == 0:
            if param.usage_count == 0:
                #print("\t" + bcolors.FAIL + f"Parameter named {param['name']} never occurred" + bcolors.ENDC)
                print("\t" + bcolors.FAIL + f"Parameter named {param.name} never occurred" + bcolors.ENDC)
            else:
                #print("\t" + bcolors.OKGREEN + f"Parameter named {param['name']}  occurred {param_occurrence_count} time(s)" + bcolors.ENDC)
                print("\t" + bcolors.OKGREEN + f"Parameter named {param.name}  occurred {param.usage_count} time(s)" + bcolors.ENDC)

                print("\t" + "\t" + f"Unique valued occurrences: {param_occurrence_count_unique}")

        if self.analysis_result['request_info_requestbody'] != "":
            print("Parameters from requestBody (OAv3)")


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


class AnomalyType(Enum):
    UNKNOWN_RESPONSE_CODE = 1
    MISSING_REQUIRED_REQUEST_PARAMETER = 2


class Anomaly:
    def __init__(self, entry, type, description):
        self.entry = entry
        self.type = type
        self.description = description


# TODO: should enum be added to location?
class Parameter:
    def __init__(self, name, location, required=False, schema=None):
        self.name = name
        self.location = location #Possibly enum? (header path query formdata body cookie, should make own requestbody?)
        self.required = required #Boolean, tämäkin vähän turha
        self.schema = schema #Schema json, ei pakollinen vielä
        self.usage_count = 0
        self.unique_values = set()

    def addUsage(self, value):
        # Increase counter and add value if uniq
        self.usage_count = self.usage_count + 1
        self.unique_values.add(value)


class ASC:
    def __init__(self, apispec_addr, har_addr, endpoints_excluded=[], coverage_level_required=0):
        self.apispec_addr = apispec_addr
        self.har_addr = har_addr

        self.apispec = ""
        self.harobject = ""

        self.options = "" # Is most likely futile

        self.endpoints = {}
        self.basepath = ""

        self.version = ""

        self.endpoints_excluded = endpoints_excluded

        self.coverage_level_required = coverage_level_required

        # Set passing of coverage initially true
        self.coverage_requirement_passed = True

    def read_har_file(self):
        # Initialize har parser object
        with open(self.har_addr, 'r') as f:
            self.harobject = HarParser(json.loads(f.read()))

    def read_api_specification(self):
        # Parse API spec to endpoint and method objects with prance parser

        # NOTICE: OA v2 seems to be working fine with openapi spec validator and swagger validator too

        specparser = ResolvingParser(self.apispec_addr, backend='openapi-spec-validator')
        #print(specparser.specification)


        # TODO: filter all allowed versions here and if spec is not supported then print error
        self.version = specparser.version

        self.apispec = specparser.specification
        paths = specparser.specification['paths']

        # Parse endpoints
        for endpoint in paths.keys():
            # Parse endpoint specific parameters if those exist

            params_endpoint = []
            if 'parameters' in paths[endpoint].keys():
                # Common parameters for endpoint exists
                for param in paths[endpoint]['parameters']:
                    params_endpoint.append(Parameter(param['name'], param['in']))

            mthds = {}

            for method in paths[endpoint].keys():
                # Operation params can override endpoint params
                params_operation = []

                if 'parameters' in paths[endpoint][method].keys():
                    # Common parameters for endpoint exists
                    for param in paths[endpoint][method]['parameters']:
                        params_operation.append(Parameter(param['name'], param['in']))

                # OpenAPI v3 has requestbody field instead of form and body parameters
                if 'requestBody' in paths[endpoint][method].keys():
                    # OA V3
                    # TODO: consider how to apply schemas in this and think requestbody things
                    params_operation.append(Parameter('requestBody', 'requestbody'))


                # Add here only params which are not duplicate (overriden endpoint params are dropped)
                params_final = []

                # Add endpoint parameters to final parameters if those are not overriden in method
                for p_e in params_endpoint:
                    if not any(p_o.name == p_e for p_o in params_operation):
                        params_final.append(p_e)


                # Add all operation parameters to final array
                params_final.extend(params_operation)

                minfo = copy.deepcopy(paths[endpoint][method])
                mthds[method] = SingleMethod(method, endpoint, minfo, params_final)
            self.endpoints[endpoint] = (Endpoint(endpoint, mthds))

    def preprocess_har_entries(self):
        # Classify and filter out har entries to correct endpoints to wait for analysis

        # Determine if any endpoint matches to har entry url and add entry to endpoint if match is found
        for page in self.harobject.pages:
            for entry in page.entries:
                url = entry['request']['url']
                endpoint_found = False
                for endpoint in self.endpoints.keys():
                    if self.endpoints[endpoint].match_url_to_path(url):
                        self.endpoints[endpoint].input_log_entry(entry)
                        endpoint_found = True
                        break

                if not endpoint_found:
                    print(f"HAR entry URL {url} does not correspond any endpoint in API specification")

    def analyze(self):
        # Trigger every endppoint analysis
        for endpoint in self.endpoints.keys():
            self.endpoints[endpoint].analyze_endpoint()

    def print_analysis_to_console(self, suppressed=False):
        # Print full analysis to console if it is not suppressed
        if suppressed:
            return

        # Export results to command line
        for endpoint in self.endpoints.keys():
            self.endpoints[endpoint].print_endpoint_analysis_to_console()

    def export_large_report_json(self):
        # Exports json report
        # Collect all dictionaries of endpoints and output them in raport

        # TODO: Determine proper json format and output as file, is schema needed?
        for endpoint in self.endpoints.keys():
            for method in self.endpoints[endpoint].methods.keys():
                print(self.endpoints[endpoint].methods[method].analysis_result)

    def analyze_coverage(self):
        '''
        Checks if given coverage level is fullfilled
        Save and return failures if it is not fullfilled
        If failures exist, return true, otherwise false in order to main function to crash program
        :return:
        '''
        # TODO: If 'treat undefined response as error' flag or something is specified, add it here accordingly
        # TODO: If coverage level 4 (=parameter coverage) is added, add it here accordingly

        # Coverage based on given level to determine if failed or not and failure reasons as string array
        coverage_level_fulfilled = True
        coverage_level_failure_reasons = []

        if self.coverage_level_required == None:
            # Failure analysis and failure report is not made at all
            pass
        if self.coverage_level_required == "1":
            # Check endpoint coverage
            for endpoint in self.endpoints.keys():
                # Skip excluded endpoints
                if endpoint in self.endpoints_excluded:
                    continue

                if not self.endpoints[endpoint].is_used():
                    coverage_level_fulfilled = False
                    # Add failure and reason
                    coverage_level_failure_reasons.append(f"Endpoint {endpoint} is not used")

        if self.coverage_level_required == "2":
            # Check method coverage
            for endpoint in self.endpoints.keys():
                # Skip excluded endpoints
                if endpoint in self.endpoints_excluded:
                    continue

                if len(self.endpoints[endpoint].get_methods_not_used()) > 0:
                    coverage_level_fulfilled = False
                    for mtd in self.endpoints[endpoint].get_methods_not_used():
                        coverage_level_failure_reasons.append(f"Endpoint's {endpoint} method {mtd} is not used")

        if self.coverage_level_required == "3":
            # Check response coverage
            for endpoint in self.endpoints.keys():
                # Skip excluded endpoints
                if endpoint in self.endpoints_excluded:
                    continue

                for mtd in self.endpoints[endpoint].methods.keys():
                    responses_not_used = self.endpoints[endpoint].methods[mtd].get_responses_not_used()
                    for resp in responses_not_used:
                        coverage_level_fulfilled = False
                        coverage_level_failure_reasons.append(f"Endpoint's {endpoint} method {mtd} response {resp} is not used")

        return coverage_level_fulfilled, coverage_level_failure_reasons


    def export_failure_report(self, failure_report_filename):
        '''
        Saves the failure report to file named filename
        Name of the file is not specified by command line args asc_failure_report_timestamp
        Overwrites file if same name exists
        Creates empty file if no failures exist
        :return:
        '''

        coverage_level_achieved, failures = self.analyze_coverage()

        self.coverage_requirement_passed = coverage_level_achieved

        # TODO: Actual schema instead of simple text file or stuff?

        with open(failure_report_filename, 'w') as file:
            for fail in failures:
                file.write(fail + "\n")

    def export_large_report_text(self):
        # TODO: Luodaan ihmisluettava iso rapsa, ei vaikutuksia ajomoodeilla, kaikki anomaliat ja vähäisetkin virheet mukaan
        pass

    def crash_program(self, suppress_crash=False):
        # Crash program with exit code 1 if needed and not suppressed
        if suppress_crash:
            return

        if not self.coverage_requirement_passed:
            # Crash program
            exit(1)

def main():
    parser = argparse.ArgumentParser(description='Calculate API spec coverage from HAR files and API spec')
    parser.add_argument('apispec', help='Api specification file')
    parser.add_argument('harfile', help='Captured traffic in HAR file format')
    parser.add_argument('failurereportname', nargs="?", type=str, default="failure_report.txt")
    parser.add_argument('--coveragelevel', help='Specify coverage level which is required to be fullfilled for program not to crash, intended to be used with jenkins builds. 100% cov expected always. 1 = endpoint coverage, 2 = method coverage, 3 = response coverage')
    parser.add_argument('--exclude', nargs='+', type=str, default=[], help='Exclude endpoints by writing exact paths of those, for example /pet or /pet/{petId}/asdfadsf ')
    parser.add_argument('--suppressconsole', help="Suppress console outputs", action='store_true')
    parser.add_argument('--dontcrashincoveragefailure', action='store_true', help="Do not crash program in the end if coverage level is not fullfilled")

    args = parser.parse_args()


    asc = ASC(args.apispec, args.harfile, coverage_level_required=args.coveragelevel, endpoints_excluded=args.exclude)

    asc.read_api_specification()
    asc.read_har_file()
    asc.preprocess_har_entries()
    asc.analyze()
    asc.print_analysis_to_console(suppressed=args.suppressconsole)
    asc.export_failure_report(args.failurereportname)
    asc.crash_program(suppress_crash=args.dontcrashincoveragefailure)


# TODO: Move both functions to utils
def get_multipart_boundary(req_entry):

    for header in req_entry['headers']:
        if header['name'] == 'content-type':
            boundarysearch = re.search('boundary=(.*?)( |$)', header['value'])
            boundvalue = boundarysearch.group(1)
            return boundvalue


# TODO: Improve readibility
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