import json
from haralyzer import HarParser, HarPage
import re
import argparse
import copy
from jsonschema import validate
from jsonschema import validators

from urllib.parse import urlparse

from enum import Enum

from prance import ResolvingParser

from jinja2 import Environment, FileSystemLoader

import time

from utils import TerminalColors, get_multipart_boundary, decode_multipart, path_parameter_extractor


class Endpoint:
    def __init__(self, path, methods, baseurl="", excluded=False):
        self.path = path
        self.methods = methods
        # Baseurl needed to eliminate changes for some weird urls in har to map incorrectly
        self.baseurl = baseurl # Baseurl currently futile?
        self.usage_count = 0
        self.excluded = excluded

        self.methods_count = len(self.methods)
        self.methods_used = 0

        # Consider if these are futile or useful
        self.response_codes_in_methods_count = 0
        self.response_codes_in_methods_used = 0

        self.default_response_codes_in_methods_count = 0
        self.default_response_codes_in_methods_used = 0

        # Make place for anomalies which do not fit into single method
        self.anomalies = []

        # TODO: Think if endpoint specific parameters must be handled differently
        # Currently they are dropped to operation level (singlemethod) when parsing

    def input_log_entry(self, entry):
        # Input entry under correct method
        method_type = entry['request']['method'].lower()

        if method_type in self.methods:
            self.methods[method_type].add_entry(entry)
            self.usage_count = self.usage_count + 1
        else:
            # Endpoint method called which does not exist
            # Make anomaly out of it
            # Consider if this is futile and this could be discarded, because it is not "touching api"
            # Not yet outputted to anywhere
            self.anomalies.append(Anomaly(
                entry=entry,
                type=AnomalyType.UNDEFINED_METHOD_OF_ENDPOINT,
                description=f"Call of undefined method {method_type} of the endpoint"
            ))

    def match_url_to_path(self, url):
        '''
        Just determines if url matches this endpoints path
        :param url:
        :param basepath:
        :return boolean:
        '''

        url_parsed = urlparse(url)

        # TODO: Consider giving endpoint also server name and other stuff to filter out some weird ulrs

        # TODO: Consider need of basepath and server because OA v3 can have multiple servers too

        # Is there some other smarter way to test path params than just looking for brackets?
        if '{' in self.path and '}' in self.path:
            # Create search pattern by replacing path parameter with 'anything-but-slash' wildcard
            # and can end with or without slash

            # Non greedy replace of path parameters
            search_pattern = re.sub('{.+?}', '[^/]+?', self.path) + "[/]?$"

            # Check if path matches to url

            if self.baseurl != "":
                search_pattern = self.baseurl + search_pattern

            if re.search(search_pattern, url_parsed.path):
                return True

        else:
            # No path parameters
            # Take also case where request have ending slash
            if url_parsed.path.endswith(self.path) or url_parsed.path.endswith(self.path + "/"):

                # Compare with base url if it is not empty
                # Still not absolutely perfect coverage of special cases but should be enough

                if self.baseurl != "":
                    if url_parsed.path.endswith(self.baseurl + self.path) or url_parsed.path.endswith(self.baseurl + self.path + "/"):
                        return True
                else:
                    return True

        # No match found
        return False

    def analyze_endpoint(self):
        for mtd in self.methods.keys():
            self.methods[mtd].analyze()

            if self.methods[mtd].is_used():
                self.methods_used += 1

        # Collect and combine information from all analyzed methods
        # Might need heavy refactoring
        for mtd in self.methods.keys():
            self.response_codes_in_methods_count += self.methods[mtd].response_codes_count
            self.response_codes_in_methods_used += self.methods[mtd].response_codes_used

            if self.methods[mtd].default_response_exists:
                self.default_response_codes_in_methods_count += 1

                if self.methods[mtd].default_response_used:
                    self.default_response_codes_in_methods_used += 1

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

    def get_as_dictionary(self):
        endpoint_dict = {
            'path': self.path,
            'usage_count': self.usage_count,
            'methods_count': self.methods_count,
            'methods_used': self.methods_used,
            'methods': {},
            'anomalies': self.anomalies
        }
        for method_type in self.methods.keys():
            endpoint_dict['methods'][method_type] = self.methods[method_type].get_as_dictionary()

        return endpoint_dict


# Class for single method
class SingleMethod:
    def __init__(self, type, path, methodinfo, parameters, responses):
        self.type = type
        self.path = path
        self.parameters = parameters
        self.methodinfo = methodinfo

        self.responses = responses

        # Array of entries
        self.logs = []

        # Array of anomalies, filled during analysis
        self.anomalies = []

        # Analysis results for reporting
        self.default_response_exists = False

        self.response_codes_count = len(responses)
        self.response_codes_used = 0

        for r in self.responses:
            if r.code == 'default':
                self.default_response_exists = True
                self.response_codes_count -= 1
                break

        self.default_response_used = False

    def add_entry(self, entry):
        # Add single entry to list
        self.logs.append(entry)

    def is_used(self):
        # returns true or false depending on count
        if len(self.logs) > 0:
            return True
        else:
            return False

    def get_usage_count(self):
        return len(self.logs)

    def get_responses_not_used(self):
        # return array of responses not used

        response_not_used = []

        for response in self.responses:
            if (response.code != 'default') and (response.usage_count == 0):
                response_not_used.append(response.code)

        return response_not_used

    def get_as_dictionary(self):
        singlemethod_dictionary = {
            'logs': self.logs,
            'usage_count': self.get_usage_count(),
            'anomalies': [],
            'parameters': [],
            'responses': [],
            'response_codes_count': self.response_codes_count,
            'response_codes_used': self.response_codes_used,
            'default_response_exists': self.default_response_exists,
            'default_response_used': self.default_response_used,
            'anomalies_count': 0
        }

        params = []
        resps = []
        anoms = []

        for r in self.responses:
            resps.append(r.get_as_dictionary())

        for p in self.parameters:
            params.append(p.get_as_dictionary())

        for a in self.anomalies:
            anoms.append(a.get_as_dictionary())

        singlemethod_dictionary['parameters'] = params
        singlemethod_dictionary['responses'] = resps
        singlemethod_dictionary['anomalies'] = anoms

        singlemethod_dictionary['anomalies_count'] = len(anoms)

        return singlemethod_dictionary

    def analyze(self):
        # Run analysis for this method and store all analysis to this singlemethods param and response objects

        # Run analysis for every log entry for this endpoint method
        for entry in self.logs:
            url = entry['request']['url']

            for param in self.parameters:
                if param.location == 'path':
                    # Use new utility function now
                    paramvalue = path_parameter_extractor(url, self.path, param.name)

                    # Path parameter can not be empty
                    param.add_usage(paramvalue)

                elif param.location == 'query':
                    # Check query parameters as default way
                    # Is query params always required?
                    parameter_found = False

                    for queryparameter in entry['request']['queryString']:
                        if queryparameter['name'] == param.name:
                            paramvalue = queryparameter['value']
                            param.add_usage(paramvalue)
                            parameter_found = True

                    # Add anomaly if required parameter does not exist
                    if param.required and not parameter_found:
                        # Anomaly because of required parameter is not found
                        self.anomalies.append(Anomaly(entry, AnomalyType.MISSING_REQUIRED_REQUEST_PARAMETER,
                                                               "Required parameter " + str(
                                                                   param.name) + " was not found in request query parameters"
                                                      ))

                elif param.location == 'header':
                    # Check request header parameters as default way
                    parameter_found = False

                    for headerparameter in entry['request']['headers']:
                        if headerparameter['name'] == param.name:
                            paramvalue = headerparameter['value']
                            param.add_usage(paramvalue)

                    # Add anomaly because request header parameter is not found
                    if param.required and not parameter_found:
                        # Anomaly because of required parameter is not found
                        self.anomalies.append(
                            Anomaly(entry, AnomalyType.MISSING_REQUIRED_REQUEST_PARAMETER,
                                    "Required parameter " + str(
                                        param.name) + " was not found in request header parameters"
                                    ))

                # Requestbody (OA V3) is treated as OA V2 body
                elif param.location in ('body', 'requestbody'):
                    # Checks and validates body content of request and treats it as one parameter
                    # Openapi V3 does not have body parameter and it is replaced by 'requestBody' object
                    paramvalue = entry['request']['postData']['text']
                    param.add_usage(paramvalue)

                    # TODO: Possibly new feature to check and handle single schema fields as parameters if needed

                    # TODO: Make better except clauses
                    try:
                        ins = json.loads(paramvalue)
                    except:
                        # Notify
                        print("Cannot parse request parameters")

                        # Add anomaly
                        self.anomalies.append(Anomaly(entry, AnomalyType.BROKEN_REQUEST_BODY,
                                                                   "Could not parse sent data object in body to json object"))

                    else:
                        # Select schema from options based on postdata mimetype
                        postdata_mimetype = entry['request']['postData']['mimeType']
                        #print(param.schemas.keys())
                        #print(entry['request']['postData']['mimeType'])
                        #print(param.schemas)

                        sch = ""

                        # Check if single schema is specified (OA v2)
                        if param.schema is not None:
                            sch = json.loads(json.dumps(param.schema))

                        # Check if schema is found from set of multiple possible schemas by mimetype (OA v3)
                        elif postdata_mimetype in param.schemas:
                            sch = json.loads(json.dumps(param.schemas[postdata_mimetype]))

                        else:
                            # TODO: Consider what kind of exceptions could happend
                            pass

                        # TODO: Make more spesific except clauses
                        try:
                            validate(instance=ins, schema=sch, cls=validators.Draft4Validator)
                        except:
                            self.anomalies.append(Anomaly(entry, AnomalyType.BROKEN_REQUEST_BODY,
                                                                       "Validator produced error when validating this request body"))

                    pass

                elif param.location == 'formData':
                    # Form data parameters can be found either params field or content field in HAR
                    # Parsing and analyzing data from there

                    if 'params' in entry['request']['postData']:
                        parameter_found = False
                        for formparam in entry['request']['postData']['params']:
                            if formparam['name'] == param.name:
                                paramvalue = formparam['value']
                                param.add_usage(paramvalue)
                                parameter_found = True

                        if not parameter_found and param.required:
                            # Make required parameter not found anomaly
                            self.anomalies.append(
                                Anomaly(entry, AnomalyType.MISSING_REQUIRED_REQUEST_PARAMETER,
                                        "Required parameter " + str(
                                            param.name) + " was not found in request form data"
                                        ))

                    elif 'text' in entry['request']['postData']:
                        # Form parameters can be found in text field of HAR too, which case special parsing is required
                        # Parse multipart data from response with custom functions

                        # TODO: getting boundary and parsed data are so tightly connected that consider combining
                        # could be used some ready multipart decoder?
                        bound = get_multipart_boundary(entry['request'])
                        parseddata = decode_multipart(str(entry['request']['postData']['text']), bound)

                        parameter_found = False
                        for p_name, paramvalue in parseddata:
                            if p_name == param.name:
                                param.add_usage(paramvalue)
                                parameter_found = True

                        if not parameter_found and param.required:
                            # Make required parameter not found anomaly
                            self.anomalies.append(
                                Anomaly(entry, AnomalyType.MISSING_REQUIRED_REQUEST_PARAMETER,
                                        "Required parameter " + str(
                                            param.name) + " was not found in request form data"
                                        ))

            # Analyzing responses
            response_code = str(entry['response']['status'])
            response_code_found = False
            for resp in self.responses:
                if resp.code == response_code:
                    response_code_found = True
                    resp.add_usage(entry['response']['content']['text'])

                    # TODO: Determine what to do with xml bodies, maybe auto detect and use XML validator
                    # Now xml bodies are just skipped

                    # If response has schema specified, compare response body content with it

                    # Transfer this to correspond new objects
                    if resp.schema is not None:
                        sch = json.loads(json.dumps(resp.schema))
                        # Try parse and validate
                        try:
                            ins = json.loads(entry['response']['content']['text'])
                            validate(instance=ins, schema=sch, cls=validators.Draft4Validator)
                        except Exception as e:
                            #print(str(e))
                            self.anomalies.append(
                                Anomaly(entry,
                                          AnomalyType.INVALID_RESPONSE_BODY,
                                          f"Validator produced validation error when validating response body. Error message:{str(e)}"))

                    break

            if not response_code_found:
                # Undefined response code detected
                # Decide if default response is present and make anomaly text based on it

                # TODO: Closer inspection on default schemas and stuff needed

                # TODO: add to anomalies like: error produced by xxx validator

                default_response_exists = False
                for resp in self.responses:
                    if resp.code == 'default':
                        default_response_exists = True
                        # Adding usage to default response
                        resp.add_usage(entry['response']['content']['text'])

                        # Validate response schema of default response
                        if resp.schema is not None:
                            sch = json.loads(json.dumps(resp.schema))
                            # Try parse and validate
                            try:
                                ins = json.loads(entry['response']['content']['text'])
                                validate(instance=ins, schema=sch, cls=validators.Draft4Validator)
                            except Exception as e:
                                self.anomalies.append(
                                    Anomaly(entry,
                                            AnomalyType.INVALID_RESPONSE_BODY,
                                            "Validator produced validation error when validating default response body. Error message:{str(e)}"))

                        break

                if default_response_exists:
                    self.anomalies.append(Anomaly(entry, AnomalyType.UNDEFINED_RESPONSE_CODE_DEFAULT_IS_SPECIFIED,
                                                               "Response code " + str(response_code) + " is not explictly defined in API specification, but default response is present"))

                else:
                    self.anomalies.append(
                        Anomaly(entry, AnomalyType.UNDEFINED_RESPONSE_CODE_DEFAULT_IS_SPECIFIED,
                                "Response code " + str(
                                    response_code) + " is not explictly defined in API specification, and default response is not present"))

        # Add calculations of parameters and responses of this endpoint
        for r in self.responses:
            if r.code != 'default':
                if r.usage_count != 0:
                    self.response_codes_used += 1
            elif r.code == 'default':
                if r.usage_count != 0:
                    self.default_response_used = True

        # TODO: Same as above with params


class Schema:
    '''
    Not yet used anywhere
    '''
    def __init__(self):
        self.payload = ""


class AnomalyType(Enum):
    UNDEFINED_RESPONSE_CODE_DEFAULT_NOT_SPECIFIED = 1
    MISSING_REQUIRED_REQUEST_PARAMETER = 2
    BROKEN_REQUEST_BODY = 3
    UNDEFINED_RESPONSE_CODE_DEFAULT_IS_SPECIFIED = 4
    BROKEN_RESPONSE_BODY = 5
    DEFAULT_RESPONSE_IS_NOT_USED = 6 # Is this error at all?
    INVALID_RESPONSE_BODY = 7
    UNDEFINED_METHOD_OF_ENDPOINT = 8


class Anomaly:
    def __init__(self, entry, type, description):
        self.entry = entry
        self.type = type
        self.description = description

    def get_as_dictionary(self):
        anomaly_dictionary = {
            'entry': self.entry,
            'type': self.type,
            'description': self.description
        }

        return anomaly_dictionary


# TODO: should enum be added to location? yes, more formal to handle i guess
# Should this be handling also requestbody?
# Should parameter class be changed to "requestparameter" or "requestcontent"
# Schemas could be dictionary of schemas...
class Parameter:
    def __init__(self, name, location, required=False, schemas=None, schema=None):
        self.name = name
        self.location = location # path, query, body, formdata etc, should enum be made?
        self.required = required #Boolean, not yet used, could be futile because cannot know if request omits it purposefully
        #self.schema = schema #Schema, not yet used

        # Use single schema with OA v2 and dictionary of multiple schemas with OA v3
        self.schema = schema
        self.schemas = schemas

        self.usage_count = 0
        self.unique_values = set()

    def add_usage(self, value):
        # Increase counter and add value if uniq
        self.usage_count = self.usage_count + 1
        self.unique_values.add(value)

    def get_unique_usage_count(self):
        return len(self.unique_values)

    def get_as_dictionary(self):
        parameter_dictionary = {
            'name': self.name,
            'location': self.location,
            'required': self.required,
            'schemas': self.schemas,
            'usage_count': self.usage_count,
            'unique_values': list(self.unique_values),
            'unique_values_count': self.get_unique_usage_count()
        }

        return parameter_dictionary


class Response:
    def __init__(self, code, schema):
        self.code = code
        # Should multiple schemas be available because those exist in api specs too?
        self.schema = schema
        self.usage_count = 0
        self.unique_body_values = set()

    def add_usage(self, value):
        # Increase counter and add value if uniq
        # Should also default response be noted?
        self.usage_count = self.usage_count + 1
        self.unique_body_values.add(value)

    def get_unique_usage_count(self):
        return len(self.unique_body_values)

    def get_as_dictionary(self):
        response_dictionary = {
            'code': self.code,
            'schema': self.schema,
            'usage_count': self.usage_count,
            'unique_body_values': list(self.unique_body_values),
            'unique_body_values_count': self.get_unique_usage_count()
        }

        return response_dictionary


class ASC:
    def __init__(self, apispec_addr, har_addr, endpoints_excluded=[], coverage_level_required=0,
                 parameter_coverage_level_required=0):
        self.apispec_addr = apispec_addr
        self.har_addr = har_addr

        self.apispec = ""
        self.harobject = ""

        self.options = "" # Is most likely futile

        self.endpoints = {}
        self.basepath = ""

        self.version = "" # Not used, is this futile?

        self.endpoints_excluded = endpoints_excluded

        self.coverage_level_required = coverage_level_required
        self.parameter_coverage_level_required = parameter_coverage_level_required

        # Set passing of coverage initially true and later analysis can change it to false
        self.coverage_requirement_passed = True

        self.total_api_usages = 0
        self.total_har_entries = 0

        # Combined information from methods, determine if this could be refactored
        self.total_response_codes_count = 0
        self.total_response_codes_used = 0
        self.total_default_responses_count = 0
        self.total_default_responses_used = 0

        self.total_methods_in_endpoints_count = 0
        self.total_methods_in_endpoints_used = 0

        # Initiation time
        self.analysis_initiated = time.strftime("%H:%M:%S %d.%m.%Y")

        # Endpoint analysis
        self.endpoints_count = 0
        self.endpoints_used = 0

        # Common API info
        self.open_api_version = "" # v2 or v3
        self.api_name = "" # info object title
        self.api_version = "" # info object version
        self.api_description = "" # info object description, not required

        # Common HAR info
        self.first_entry_in_har_time = ""

    def read_har_file(self):
        # Initialize har parser object
        with open(self.har_addr, 'r') as f:
            self.harobject = HarParser(json.loads(f.read()))

    def read_api_specification(self):
        # Parse API spec to endpoint and method objects with prance parser

        # NOTICE: OA v2 seems to be working fine with openapi spec validator and swagger validator too
        try:
            specparser = ResolvingParser(self.apispec_addr, backend='openapi-spec-validator')
        except Exception as e:
            print("Cannot parse API specification")
            print("Error message:")
            print(str(e))
            exit(1)

        self.version = specparser.version

        self.apispec = specparser.specification
        paths = specparser.specification['paths']

        info_object = specparser.specification['info']

        self.api_name = info_object['title']
        self.api_version = info_object['version']

        if 'description' in info_object.keys():
            self.api_description = info_object['description']

        # Parse endpoints
        for endpoint in paths.keys():
            # Parse endpoint specific parameters if those exist
            # TODO: Need to think how schemas are appended here
            params_endpoint = []
            if 'parameters' in paths[endpoint].keys():
                # Common parameters for endpoint exists
                for param in paths[endpoint]['parameters']:
                    param_required = False
                    if 'required' in param:
                        param_required = param['required']

                    params_endpoint.append(Parameter(param['name'], param['in'], required=param_required))

            mthds = {}

            for method in paths[endpoint].keys():
                # Operation params can override endpoint params
                params_operation = []

                # TODO: Need tho think if common responses affect these
                responses_operation = []

                if 'parameters' in paths[endpoint][method].keys():
                    # Common parameters for endpoint exists
                    for param in paths[endpoint][method]['parameters']:
                        param_required = False

                        # Use schemas for OA v3 and schema for OA v2
                        schema = None
                        if 'required' in param:
                            param_required = param['required']

                        # OA V2 only 1 schema available and parameter is always in body

                        # Parameter can have only one schema

                        if 'schema' in param:
                            schema = param['schema']

                        params_operation.append(Parameter(param['name'], param['in'],
                                                          required=param_required,
                                                          schema=schema))

                # Responses
                # TODO: Consider if this should be changed to dict of responses (otherwise same, key as response code)
                for code in paths[endpoint][method]['responses'].keys():
                    # Get schema if it exists
                    schema = None
                    if 'schema' in paths[endpoint][method]['responses'][code].keys():
                        # Openapi V2
                        schema = paths[endpoint][method]['responses'][code]['schema']

                    elif 'content' in paths[endpoint][method]['responses'][code].keys():
                        # Openapi v3
                        if 'schema' in paths[endpoint][method]['responses'][code]['content'].keys():
                            # TODO: Determine what to do because multiple schemas for xml/json can be in spec
                            pass

                    responses_operation.append(Response(code, schema))

                # OpenAPI v3 has requestbody field instead of form and body parameters
                if 'requestBody' in paths[endpoint][method].keys():
                    # OA V3
                    # TODO: consider how to apply schemas in this and think requestbody things

                    # Collect schemas
                    schemas = {}
                    for media_type, media_object in paths[endpoint][method]['requestBody']['content'].items():
                        if 'schema' in media_object:
                            schemas[media_type] = media_object['schema']

                    params_operation.append(Parameter('requestBody', 'requestbody', schemas=schemas))

                # Add here only params which are not duplicate (overriden endpoint params are dropped)
                params_final = []

                # Add endpoint parameters to final parameters if those are not overriden in method
                for p_e in params_endpoint:
                    if not any(p_o.name == p_e for p_o in params_operation):
                        params_final.append(p_e)

                # Add all operation parameters to final array
                params_final.extend(params_operation)

                minfo = copy.deepcopy(paths[endpoint][method])

                # Input responses and parameters to single method
                mthds[method] = SingleMethod(method, endpoint, minfo, params_final, responses_operation)

            # Create endpoint with list of method objects
            self.endpoints[endpoint] = (Endpoint(endpoint, mthds))

    def preprocess_har_entries(self):
        # Classify and filter out har entries to correct endpoints to wait for analysis

        # Determine if any endpoint matches to har entry url and add entry to endpoint if match is found

        for page in self.harobject.pages:
            for entry in page.entries:
                self.total_har_entries = self.total_har_entries + 1
                url = entry['request']['url']
                endpoint_found = False
                for endpoint in self.endpoints.keys():
                    if self.endpoints[endpoint].match_url_to_path(url):
                        self.endpoints[endpoint].input_log_entry(entry)
                        endpoint_found = True
                        self.total_api_usages = self.total_api_usages + 1
                        break

                # TODO: Consider if this should be saved too to final reporting?
                if not endpoint_found:
                    print(f"HAR entry URL {url} does not correspond any endpoint in API specification")

    def analyze(self):
        # Trigger every endppoint analysis
        for endpoint in self.endpoints.keys():
            self.endpoints[endpoint].analyze_endpoint()

            # Collect info from endpoint after it has been analyzed
            self.total_response_codes_count += self.endpoints[endpoint].response_codes_in_methods_count
            self.total_response_codes_used += self.endpoints[endpoint].response_codes_in_methods_count

            self.total_default_responses_count += self.endpoints[endpoint].default_response_codes_in_methods_count
            self.total_default_responses_used += self.endpoints[endpoint].default_response_codes_in_methods_used

            self.total_methods_in_endpoints_count += self.endpoints[endpoint].methods_count
            self.total_methods_in_endpoints_used += self.endpoints[endpoint].methods_used

            if self.endpoints[endpoint].is_used():
                self.endpoints_used += 1

        # Endpoints total count
        self.endpoints_count = len(self.endpoints)

    def print_analysis_to_console(self, suppress_anomalies):

        # Get calculated data as basic dictionary form and output it sensibly to console
        data = self.get_all_report_data_as_dictionary()

        print("Common info")
        print(f"OpenAPI version {data['open_api_version']}")
        print(f"API name: {data['api_name']}")
        print(f"API description: {data['api_description']}")
        print(f"API version: {data['api_version']}")

        print(f"Total API usages: {data['total_api_usages']}")

        for endpoint in data['endpoints']:
            print(TerminalColors.HEADER + f"Endpoint {endpoint['path']}" + TerminalColors.ENDC)

            usage_count_color = TerminalColors.OKGREEN
            if endpoint['usage_count'] == 0:
                usage_count_color = TerminalColors.FAIL

            print("\t" + usage_count_color + f"Usage count {endpoint['usage_count']}" + TerminalColors.ENDC)

            for method_type, method in endpoint['methods'].items():
                print("\t" + TerminalColors.HEADER + f"Method type {method_type}" + TerminalColors.ENDC)

                usage_count_color = TerminalColors.OKGREEN

                if method['usage_count'] == 0:
                    usage_count_color = TerminalColors.FAIL

                print("\t" + "\t" + usage_count_color + f"Usage count {method['usage_count']}" + TerminalColors.ENDC)

                print("\t" + "Parameters")
                for parameter in method['parameters']:
                    print("\t" + "\t" + f"Parameter name {parameter['name']}")
                    usage_count_color = TerminalColors.OKGREEN

                    if parameter['usage_count'] == 0:
                        usage_count_color = TerminalColors.FAIL

                    print("\t" + "\t" + "\t" +usage_count_color + f"Usage count {parameter['usage_count']}" + TerminalColors.ENDC)

                    print("\t" + "\t" + "\t" + f"Unique values count {parameter['unique_values_count']}")

                print("\t" + "Responses")
                for response in method['responses']:
                    print("\t" + "\t" + f"Response {response['code']}")
                    usage_count_color = TerminalColors.OKGREEN

                    if response['usage_count'] == 0:
                        usage_count_color = TerminalColors.FAIL

                    print("\t" + "\t" + "\t" + usage_count_color + f"Usage count {response['usage_count']}" + TerminalColors.ENDC)

                    print("\t" + "\t" + "\t" + f"Unique response bodies count {response['unique_body_values_count']}")

                print("\t" + f"Anomaly count: {method['anomalies_count']}")

                if (suppress_anomalies is False) and (method['anomalies_count'] > 0):
                    print("\t" + "\t" +"Anomalies")
                    for anomaly in method['anomalies']:
                        print(anomaly['description'])
                        print(anomaly['entry'])

    def export_large_report_json(self):
        # Exports json report
        # Collect all dictionaries of endpoints and output them in raport

        # TODO: Determine proper json format and output as file, is schema needed?
        for endpoint in self.endpoints.keys():
            for method in self.endpoints[endpoint].methods.keys():
                pass
                #analysis result does not exist anymore
                #print(self.endpoints[endpoint].methods[method].analysis_result)

    def analyze_coverage(self):
        '''
        Checks if given coverage level is fullfilled
        Save and return failures if it is not fullfilled
        If failures exist, return true, otherwise false in order to main function to crash program
        :return:
        '''
        # TODO: If 'treat undefined response as error' flag or something is specified, add it here accordingly
        # TODO: Does it make sense to use enums as coverage levels, argparse should support, at least argparse-utils

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

        if self.parameter_coverage_level_required in ["1", "2"]:
            # Check parameter coverage
            # Every mentioned api parameter must be used once
            # TODO: Parameter exclusion, how to implement?
            for endpoint in self.endpoints.keys():
                # Skip excluded endpoints
                if endpoint in self.endpoints_excluded:
                    continue

                for mtd in self.endpoints[endpoint].methods.keys():
                    for param in self.endpoints[endpoint].methods[mtd].parameters:
                        if self.parameter_coverage_level_required == "1":
                            if param.usage_count == 0:
                                coverage_level_fulfilled = False
                                coverage_level_failure_reasons.append(f"Endpoint's {endpoint} method's' {mtd} parameter {param.name} not used")
                        elif self.parameter_coverage_level_required == "2":
                            if len(param.unique_values) < 2:
                                coverage_level_fulfilled = False
                                coverage_level_failure_reasons.append(f"Endpoint's {endpoint} method's' {mtd} parameter {param.name} used uniquely {len(param.unique_values)} times. 2 unique usages required to fullfill this coverage requirement")

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

    def export_anomaly_report(self, anomaly_report_filename):
        '''
        :param anomaly_report_filename:
        Creates report listing only anomalies
        Anomalies categorized under each endpoint and type
        :return:
        '''
        # TODO: Is it sensible to use anomaly type as only numeric enum
        with open(anomaly_report_filename, 'w') as file:

            for endpoint in self.endpoints.keys():
                for method in self.endpoints[endpoint].methods.keys():
                    header = f"Endpoint {endpoint} - method {method.upper()} \n"
                    file.write(header)
                    # TODO: do sorting
                    # TODO: subheadering
                    for anomaly in self.endpoints[endpoint].methods[method].anomalies:
                        #print(anomaly)
                        file.write(anomaly.description + "\n")
                        file.write(str(anomaly.entry) + "\n")

    def get_all_report_data_as_dictionary(self):

        all_data_dictionary = {
            'open_api_version': self.open_api_version,
            'api_name': self.api_name,
            'api_description': self.api_description,
            'api_version': self.api_version,

            'total_api_usages': self.total_api_usages,
            'total_har_entries': self.total_har_entries,
            'first_entry_in_har_time': self.first_entry_in_har_time,
            'analysis_initiation_time': self.analysis_initiated,
            'endpoints': [],
            'total_endpoints_count': self.endpoints_count,
            'total_endpoints_used': self.endpoints_used,
            'total_response_codes_count': self.total_response_codes_count,
            'total_response_codes_used': self.total_response_codes_used,
            'total_default_responses_count': self.total_default_responses_count,
            'total_default_responses_used': self.total_default_responses_used,
            'total_methods_in_endpoints_count': self.total_methods_in_endpoints_count,
            'total_methods_in_endpoints_used': self.total_methods_in_endpoints_used
        }

        endpoint_dictionaries = []

        for e in self.endpoints:
            endpoint_dictionaries.append(self.endpoints[e].get_as_dictionary())

        all_data_dictionary['endpoints'] = endpoint_dictionaries

        return all_data_dictionary

    def export_large_report_text(self):
        all_data = self.get_all_report_data_as_dictionary()

        # print(json.dumps(self.get_all_report_data_as_dictionary(), sort_keys=True, indent=4))

        env = Environment(
            loader=FileSystemLoader('Templates/')
        )

        template = env.get_template('large_report.txt')

        template.stream(data=all_data).dump('large_report_output.txt')

    def crash_program(self, suppress_crash=False):
        # Crash program with exit code 1 if needed and not suppressed
        # This intends to serve Jenkins or other CI tool purposes to indicate that testing is not good enough
        if suppress_crash:
            return

        if not self.coverage_requirement_passed:
            # Crash program
            exit(1)


def main():
    # TODO: Add anomaly type exclusion to command line parameters

    failurereportname = "failure_report.txt"
    anomalyreportname = "anomaly_report.txt"

    parser = argparse.ArgumentParser(description='Calculate API spec coverage from HAR files and API spec')
    parser.add_argument('apispec', help='Api specification file')
    parser.add_argument('harfile', help='Captured traffic in HAR file format')
    parser.add_argument('failurereportname', nargs="?", type=str, default=failurereportname, help=f"Name of failure report, if not given default is {failurereportname}. If similar named file exist, it will be overwritten.")
    parser.add_argument('anomalyreportname', nargs="?", type=str, default=anomalyreportname,
                        help=f"Name of failure report, if not given default is {anomalyreportname}. If similar named file exist, it will be overwritten.")
    parser.add_argument('--coveragelevel', help='Specify coverage level which is required to be fullfilled for program not to crash, intended to be used with jenkins builds. full coverage expected always on next things. 1 = endpoint coverage, 2 = method coverage, 3 = response coverage')
    parser.add_argument('--parametercoveragelevel', help='Specify parameter coverage level which is required to be fullfilled for program not to crash, intended to be used with jenkins builds. 1 = require parameter to be used at least once, 2 = require parameter to be used with 2 unique values')
    parser.add_argument('--exclude', nargs='+', type=str, default=[], help='Exclude endpoints by writing exact paths of those, for example /pet or /pet/{petId}/asdfadsf ')
    parser.add_argument('--suppressconsole', help="Suppress console outputs", action='store_true')
    parser.add_argument('--suppressconsoleanomalies', help="Suppress listing of full anomalies in console output", action='store_true')
    parser.add_argument('--dontcrashincoveragefailure', action='store_true', help="Do not crash program in the end if coverage level is not fullfilled")

    args = parser.parse_args()

    asc = ASC(args.apispec, args.harfile, coverage_level_required=args.coveragelevel, endpoints_excluded=args.exclude,
              parameter_coverage_level_required=args.parametercoveragelevel)

    asc.read_api_specification()
    asc.read_har_file()
    asc.preprocess_har_entries()
    asc.analyze()
    asc.print_analysis_to_console(False)
    asc.export_failure_report(args.failurereportname)
    asc.export_anomaly_report(args.anomalyreportname)
    asc.export_large_report_text()
    asc.crash_program(suppress_crash=args.dontcrashincoveragefailure)


if __name__ == '__main__':
    main()