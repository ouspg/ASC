import json
from haralyzer import HarParser, HarPage
import re
import argparse
from jsonschema import validate
from jsonschema import validators
from jsonschema import ValidationError
from urllib.parse import urlparse
from enum import Enum
from prance import ResolvingParser
from jinja2 import Environment, FileSystemLoader
import time
import configparser
from requests_toolbelt.multipart import decoder
from utils import TerminalColors, path_parameter_extractor, find_best_mimetype_match_for_content_header
import sys
import os

import itertools

# Setting location for template directory to make script executable easily from other direcotries
PATH_TO_TEMPLATES_DIRECTORY = 'Templates'

if os.path.dirname(sys.argv[0]) != '':
    PATH_TO_TEMPLATES_DIRECTORY = os.path.dirname(sys.argv[0]) + '/Templates'


class Endpoint:
    def __init__(self, path, methods, server_address="", basepath=""):
        self.path = path
        self.methods = methods
        # Baseurl needed to eliminate changes for some weird urls in har to map incorrectly
        # Should also server url be specified?

        self.server_address = server_address
        self.basepath = basepath

        self.usage_count = 0

        self.methods_count = len(self.methods)
        self.methods_used = 0

        # Consider if these are futile or useful
        self.response_codes_in_methods_count = 0
        self.response_codes_in_methods_used = 0

        self.default_response_codes_in_methods_count = 0
        self.default_response_codes_in_methods_used = 0

        # Not in use right now
        self.required_parameters_in_methods_count = "NA"
        self.required_parameters_in_methods_used = "NA"

        self.parameters_in_methods_count = 0
        self.parameters_in_methods_used = 0

        # Make place for anomalies which do not fit into single method
        self.anomalies = []

        # Currently endpoint level parameters are dropped to operation level (singlemethod) during parsing
        # Operation level can override endpoint parameters, so it feels logically to handle those always there
        # Endpoint should be coded to handle them too if necessary

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
            self.anomalies.append(Anomaly(
                entry=entry,
                type=AnomalyType.UNDEFINED_METHOD_OF_ENDPOINT,
                description=f"Call of undefined method {method_type} of the endpoint"
            ))

    def match_url_to_path(self, url, use_path_parameters=True):
        '''
        Just determines if url matches this endpoints path
        :param url:
        :param basepath:
        :param use_path_parameters:
        :return boolean:
        '''

        # First round url match check should consider always matching non-path parameter paths
        # Because url path like /user/login would not accidentally match to /user/{username}
        # So if use_path_parameters is set to false and path parameters are present, automatical false response should be result

        url_parsed = urlparse(url)

        # Server and basepath should always be given, even if matching should succeed with empty paths too

        if '{' in self.path and '}' in self.path:
            # Path variable(s) exists

            # Produce automatical false if path parameters are forbidden on search
            if not use_path_parameters:
                return False

            # Server address exists
            if self.server_address != "":
                endpoint_path_to_compare = self.server_address + self.basepath + self.path
                url_path_to_compare = url_parsed.netloc + url_parsed.path

                # Take full match
                # No trailing slashes allowed
                search_pattern = "^" + re.sub('{.+?}', '[^/]*?', endpoint_path_to_compare) + "$"

                if re.search(search_pattern, url_path_to_compare):
                    return True
            else:
                endpoint_path_to_compare = self.basepath + self.path
                url_path_to_compare = url_parsed.path

                # Strict matching, do not allow trailing slash
                # Take full match from path
                # search_pattern = re.sub('{.+?}', '[^/]+?', endpoint_path_to_compare) + "[/]?$"
                search_pattern = re.sub('{.+?}', '[^/]*?', endpoint_path_to_compare) + "$"

                if re.search(search_pattern, url_path_to_compare):
                    return True
        else:
            # No path parameters present, so simple matching possible
            # Server address available, try full path match
            if self.server_address != "":
                endpoint_path_to_compare = self.server_address + self.basepath + self.path
                url_path_to_compare = url_parsed.netloc + url_parsed.path

                # Lets go with strict matching, no trailing slash is accepted
                if endpoint_path_to_compare == url_path_to_compare:
                    return True
                else:
                    return False
            else:
                # Match with endswith
                endpoint_path_to_compare = self.basepath + self.path
                url_path_to_compare = url_parsed.path

                if endpoint_path_to_compare == url_path_to_compare:
                    return True
                else:
                    return False

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

            # Calculate parameters and usages
            self.parameters_in_methods_count += len(self.methods[mtd].parameters)
            self.parameters_in_methods_used += self.methods[mtd].parameters_used

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
            'response_codes_in_methods_count': self.response_codes_in_methods_count,
            'response_codes_in_methods_used': self.response_codes_in_methods_used,
            'parameters_in_methods_count': self.parameters_in_methods_count,
            'parameters_in_methods_used': self.parameters_in_methods_used,
            'methods': {},
            'anomalies': self.anomalies
        }
        for method_type in self.methods.keys():
            endpoint_dict['methods'][method_type] = self.methods[method_type].get_as_dictionary()

        return endpoint_dict


# Class for single method
class SingleMethod:
    def __init__(self, type, path, unique_id, parameters, responses):
        self.type = type
        self.path = path
        self.parameters = parameters
        self.unique_id = unique_id
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

        self.parameters_used = 0

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
            if response.usage_count == 0:
                response_not_used.append(response.code)

        return response_not_used

    def get_as_dictionary(self):
        singlemethod_dictionary = {
            'method_unique_id': self.unique_id,
            'logs': self.logs,
            'usage_count': self.get_usage_count(),
            'anomalies': [],
            'parameters': [],
            'responses': [],
            'response_codes_count': self.response_codes_count,
            'response_codes_used': self.response_codes_used,
            'default_response_exists': self.default_response_exists,
            'default_response_used': self.default_response_used,
            'anomalies_count': 0,
            'parameters_used': self.parameters_used,
            'parameters_count': len(self.parameters)
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
                    # Use self-written simple parameter extractor
                    paramvalue = path_parameter_extractor(url, self.path, param.name)

                    # If path parameter is empty, add anomaly because path parameter is always required
                    if paramvalue == "":
                        self.anomalies.append(Anomaly(entry, AnomalyType.MISSING_REQUIRED_REQUEST_PARAMETER,
                                                  "Required parameter " + str(
                                                      param.name) + " was not found in request path parameters"
                                                      ))
                    else:
                        param.add_usage(paramvalue)

                elif param.location == 'query':
                    # Check query parameters as default way
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
                elif param.location == 'cookie':
                    # Cookie parameters are only available in OpenApi V3 spec
                    parameter_found = False
                    for cookieparameter in entry['request']['cookies']:
                        if cookieparameter['name'] == param.name:
                            paramvalue = cookieparameter['value']
                            param.add_usage(paramvalue)
                            parameter_found = True

                    if param.required and not parameter_found:
                        self.anomalies.append(Anomaly(entry, AnomalyType.MISSING_REQUIRED_REQUEST_PARAMETER,
                                                 "Required parameter " + str(
                                                     param.name) + " was not found in request cookie parameters"
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
                elif param.location == 'body':
                    # Checks and validates body content of request and treats it as one parameter
                    # Openapi V3 does not have body parameter and it is replaced by 'requestBody' object

                    # Some traffic capture tools do not include post data even if it have existed
                    # In this case, it will be treated similarly than there would be only empty requestbody
                    paramvalue = ''
                    try:
                        paramvalue = entry['request']['postData']['text']
                    except KeyError:
                        # Fall through for now
                        pass

                    # Check for empty body, because body parameter or requestbody parameter can be not required too
                    if (paramvalue == '') and param.required:
                        # Add anomaly for missing body if it is required
                        self.anomalies.append(
                            Anomaly(entry, AnomalyType.MISSING_REQUIRED_REQUEST_PARAMETER,
                                    "Required parameter " + str(
                                        param.name) + " but request body is empty"
                                    ))
                    else:
                        # Add body parameter usage if it is not empty and start analyzing schema
                        param.add_usage(paramvalue)

                        try:
                            ins = json.loads(paramvalue)
                        except json.JSONDecodeError as e:
                            # Add anomaly
                            self.anomalies.append(Anomaly(entry, AnomalyType.BROKEN_REQUEST_BODY,
                                                                "Could not parse sent data object in body to json object." +
                                                                f"Error message: {str(e)}"))

                        else:
                            # Select schema from options based on postdata mimetype
                            postdata_mimetype = entry['request']['postData']['mimeType']

                            # Schema selection, select best matching schema
                            selected_schema = find_best_mimetype_match_for_content_header(param.schemas.keys(), postdata_mimetype)

                            # If there was no schema, make anomaly
                            if not selected_schema:
                                self.anomalies.append(Anomaly(entry, AnomalyType.UNMATCHED_REQUEST_BODY_MIMETYPE,
                                                             f"Can not find any matching request mimetype from API specification for {postdata_mimetype}"))

                            else:
                                # Load schema which was found
                                sch = json.loads(json.dumps(param.schemas[selected_schema]))

                                try:
                                    validate(instance=ins, schema=sch, cls=validators.Draft4Validator)
                                except ValidationError as e:
                                    self.anomalies.append(Anomaly(entry, AnomalyType.BROKEN_REQUEST_BODY,
                                                                               "Validator produced error when validating this request body" +
                                                                                f"Error {str(e)}"
                                                                  ))
                                except json.decoder.JSONDecodeError as e:
                                    self.anomalies.append(
                                        Anomaly(entry,
                                                AnomalyType.BROKEN_REQUEST_BODY,
                                                f"JSON parsing error when parsing request body. Error message:{str(e)}"))

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
                        # Parsing form data with toolbelt.MultipartDecoder
                        parameter_found = False

                        postdata_contenttype = ""
                        for header in entry['request']['headers']:
                            if header['name'] == 'content-type':
                                postdata_contenttype = header['value']
                                break

                        # Stop processing and make common type anomaly if content type is not found
                        # If content type exist, continue to parsing
                        if postdata_contenttype == "":
                            self.anomalies.append(
                            Anomaly(entry, AnomalyType.OTHER_ANOMALY,
                                    "Request does not contain content-type header, unable to parse formdata"
                                    ))

                        else:
                            # Multipartdecoder wants content to be bytestring
                            form_postdata_textcontent = bytes(entry['request']['postData']['text'], encoding='utf-8')

                            dc = decoder.MultipartDecoder(form_postdata_textcontent, postdata_contenttype)

                            for part in dc.parts:
                                # Parse name field out of content-disposition
                                key_for_dict = b'Content-Disposition'
                                header_values = part.headers[key_for_dict].split(b"; ")
                                name = ""
                                for header_value in header_values:
                                    if header_value.startswith(b'name="'):
                                        name = re.search('name="(.*?)"', str(header_value)).group(1)

                                if name == param.name:
                                    param.add_usage(part.text)
                                    parameter_found = True
                                    break

                            if not parameter_found and param.required:
                                # Make required parameter not found anomaly
                                self.anomalies.append(
                                    Anomaly(entry, AnomalyType.MISSING_REQUIRED_REQUEST_PARAMETER,
                                            "Required parameter " + str(
                                                param.name) + " was not found in request form data"
                                            ))

            # Analyzing responses
            response_code = str(entry['response']['status'])
            response_code_found_explicit_definition = False
            response_code_found_range_definition = False
            response_code_range_definition = ""
            response_code_found_default_definition = False

            # First, determine if seen response code is defined, range defined or default defined
            for resp in self.responses:
                # Checking if response has explicit definition
                if resp.code == response_code:
                    response_code_found_explicit_definition = True
                    break

                # Checking if response has range definition
                if resp.code in ['1XX', '2XX', '3XX', '4XX', '5XX']:
                    # Check if traffic entry fits into that range definition by companing first number
                    if response_code[0] == resp.code[0]:
                        response_code_found_range_definition = True
                        response_code_range_definition = resp.code

                if resp.code == 'default':
                    response_code_found_default_definition = True

            # Determine in which definition response falls
            response_selection = ""
            if response_code_found_explicit_definition:
                response_selection = response_code
            elif response_code_found_range_definition:
                response_selection = response_code_range_definition
            elif response_code_found_default_definition:
                self.anomalies.append(Anomaly(entry, AnomalyType.UNDEFINED_RESPONSE_CODE_DEFAULT_IS_SPECIFIED,
                                              "Response code " + str(
                                                  response_code) + " is not explictly defined in API specification, but default response is present"))
                response_selection = 'default'
            else:
                # No response codes corresponding traffic entry, make anomaly
                self.anomalies.append(
                    Anomaly(entry, AnomalyType.UNDEFINED_RESPONSE_CODE_DEFAULT_NOT_SPECIFIED,
                            "Response code " + str(
                                response_code) + " is not explictly defined in API specification, and default response is not present"))

            # Decent response definition is found, start processing
            if response_selection is not "":
                for resp in self.responses:
                    if resp.code == response_selection:

                        # Text field in har is optional, treat missing har as empty request body for now
                        if 'text' in entry['response']['content']:
                            resp.add_usage(entry['response']['content']['text'])
                        else:
                            resp.add_usage("")

                        # Currently only limited json body validation is supported

                        response_mimetype = entry['response']['content']['mimeType']

                        # If schemas not available (schemas dictionary is empty), do not start validation
                        if not resp.schemas:
                            # No schemas available, do not continue processing
                            break

                        # Schema selection for analysis
                        selected_schema = find_best_mimetype_match_for_content_header(resp.schemas.keys(),
                                                                                      response_mimetype)
                        # If there was no suitable schema or schema is not existing at all
                        if not selected_schema:
                            self.anomalies.append(Anomaly(entry, AnomalyType.UNMATCHED_REQUEST_BODY_MIMETYPE,
                                                          f"Can not find any matching response schema mimetype from API specification for {response_mimetype}"))
                        else:
                            sch = json.loads(json.dumps(resp.schemas[selected_schema]))

                            # Try parse and validate
                            try:
                                ins = json.loads(entry['response']['content']['text'])
                                validate(instance=ins, schema=sch, cls=validators.Draft4Validator)
                            except json.decoder.JSONDecodeError as e:
                                self.anomalies.append(
                                    Anomaly(entry,
                                            AnomalyType.BROKEN_RESPONSE_BODY,
                                            f"JSON parsing error when parsing response body. Error message:{str(e)}"))

                            except ValidationError as e:
                                self.anomalies.append(
                                    Anomaly(entry,
                                              AnomalyType.INVALID_RESPONSE_BODY,
                                              f"Validator produced validation error when validating response body. Error message:{str(e)}"))

                        break

        # Calculations of parameters and responses of this endpoint
        for r in self.responses:
            if r.code != 'default':
                if r.usage_count != 0:
                    self.response_codes_used += 1
            elif r.code == 'default':
                if r.usage_count != 0:
                    self.default_response_used = True

        for p in self.parameters:
            if p.usage_count > 0:
                self.parameters_used += 1


class Schema:
    '''
    Not yet used anywhere
    '''
    def __init__(self):
        self.payload = ""

# Anomalies have enum types describing them
# "Other anomaly" is for all uncommon misc types and anomaly description must be provided in anomaly entry description


class AnomalyType(Enum):
    UNDEFINED_RESPONSE_CODE_DEFAULT_NOT_SPECIFIED = 1
    MISSING_REQUIRED_REQUEST_PARAMETER = 2
    BROKEN_REQUEST_BODY = 3
    UNDEFINED_RESPONSE_CODE_DEFAULT_IS_SPECIFIED = 4
    BROKEN_RESPONSE_BODY = 5
    INVALID_RESPONSE_BODY = 6
    UNDEFINED_METHOD_OF_ENDPOINT = 7
    UNMATCHED_REQUEST_BODY_MIMETYPE = 8
    OTHER_ANOMALY = 9


class Anomaly:
    # Making anomaly to have unique id
    iter_id = itertools.count()

    def __init__(self, entry, type, description):
        self.entry = entry
        self.type = type
        self.description = description
        self.unique_id = next(Anomaly.iter_id)

    def get_as_dictionary(self):
        anomaly_dictionary = {
            'entry': self.entry,
            'type': self.type.value,
            'description': self.description,
            'unique_id': self.unique_id
        }

        return anomaly_dictionary


class Parameter:
    def __init__(self, name, location, required=False, schemas={}):
        self.name = name

        # Location can be path, query, body, header, formdata or cookie
        self.location = location
        self.required = required

        # Schemas of the parameter are stored in mimetype -> schema dictionary
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
    def __init__(self, code, schemas={}):
        self.code = code

        # Possible schemas in mimetype -> schema dictionary
        self.schemas = schemas

        # Mimetype based schema
        self.usage_count = 0
        self.unique_body_values = set()

    def add_usage(self, value):
        # CHECK: Is default response calculated correctly
        self.usage_count = self.usage_count + 1
        self.unique_body_values.add(value)

    def get_unique_usage_count(self):
        return len(self.unique_body_values)

    def get_as_dictionary(self):
        response_dictionary = {
            'code': self.code,
            'schema': self.schemas,
            'usage_count': self.usage_count,
            'unique_body_values': list(self.unique_body_values),
            'unique_body_values_count': self.get_unique_usage_count()
        }

        return response_dictionary


# Api coverage level setting enum
class ApiCoverageLevel(Enum):
    COVERAGE_DISABLED = 0
    COVERAGE_ENDPOINT = 1
    COVERAGE_METHOD = 2
    COVERAGE_RESPONSE = 3


# Parameter coverage level setting enum
class ParameterCoverageLevel(Enum):
    COVERAGE_DISABLED = 1
    COVERAGE_USED_ONCE = 2
    COVERAGE_USED_TWICE_UNIQUELY = 3


class ASC:
    def __init__(self, apispec_addr, har_addr, endpoints_excluded, coverage_level_required,
                 parameter_coverage_level_required, coverage_level_default_response_as_normal_code, anomaly_types_causing_crash, server_address,
                 server_basepath):
        self.apispec_addr = apispec_addr
        self.har_addr = har_addr

        self.apispec = ""
        self.harobject = ""

        self.endpoints = {}

        # OpenAPI v3 has possibility to contain multiple servers, but calculations support only one server and basepath
        self.server_address = server_address
        self.server_basepath = server_basepath

        self.endpoints_excluded = endpoints_excluded

        self.coverage_level_required = coverage_level_required
        self.parameter_coverage_level_required = parameter_coverage_level_required

        self.coverage_default_response_as_normal_response = coverage_level_default_response_as_normal_code

        # Set passing of coverage and anomaly encounter initially true and later analysis can change it to false
        self.coverage_requirement_passed = True
        self.anomaly_requirements_passed = True

        # Total usage and entry counters
        self.total_api_usages = 0
        self.total_har_entries = 0

        # Combined information from methods, determine if this could be refactored
        self.total_response_codes_count = 0
        self.total_response_codes_used = 0
        self.total_default_responses_count = 0
        self.total_default_responses_used = 0

        self.total_methods_in_endpoints_count = 0
        self.total_methods_in_endpoints_used = 0

        # Not yet used
        self.total_required_parameters_count = "NA"
        self.total_required_parameters_used = "NA"

        self.total_parameters_count = 0
        self.total_parameters_used = 0

        # Initiation time
        self.analysis_initiated = time.strftime("%H:%M:%S %d.%m.%Y")

        # Endpoint analysis
        self.endpoints_count = 0
        self.endpoints_used = 0

        # Common API info from api specification file
        self.open_api_version = ""
        self.api_name = ""
        self.api_version = ""
        self.api_description = ""

        # Request URLs which are not touching api
        self.har_filtered_out_request_urls = []

        # Anomaly types, which will cause the crash of program aka "critical anomalies"
        self.anomaly_types_causing_crash = anomaly_types_causing_crash

        # Results from coverage analysis
        self.coverage_level_failure_reasons = []

        # Results from anomaly analysis
        self.anomalies_all = []
        self.anomalies_critical = []

    def read_har_file(self):
        # Initialize har parser object
        # Har specification demands file to be encoded with UTF-8

        # utf-8-sig should automatically handle the situation when BOM is present
        with open(self.har_addr, 'r', encoding="utf-8-sig") as f:
            self.harobject = HarParser(json.loads(f.read()))

    def read_api_specification(self):
        # Parse API spec to endpoint and method objects with prance parser

        # NOTICE: OA v2 seems to be working fine with openapi spec validator and swagger validator too
        # NOTICE: Json seems to be working always, but some cases yaml fails
        #   - This is probably because yaml might not have strings quoted
        try:
            specparser = ResolvingParser(self.apispec_addr, backend='openapi-spec-validator')
        except Exception as e:
            print("Cannot parse API specification")
            print("Error message:")
            print(str(e))
            exit(1)

        self.apispec = specparser.specification
        paths = specparser.specification['paths']

        info_object = specparser.specification['info']

        self.api_name = info_object['title']
        self.api_version = info_object['version']

        # Get openapi/swagger version number
        if 'openapi' in specparser.specification:
            self.open_api_version = specparser.specification['openapi']
        if 'swagger' in specparser.specification:
            self.open_api_version = specparser.specification['swagger']

        if 'description' in info_object.keys():
            self.api_description = info_object['description']

        # Parse endpoints
        for endpoint in paths.keys():
            # Parse endpoint specific parameters if those exist
            # Both oa specses seems to have their endpoint-specific parameters here
            params_endpoint = []
            if 'parameters' in paths[endpoint].keys():
                # Common parameters for endpoint exists
                for param in paths[endpoint]['parameters']:
                    param_required = False
                    if 'required' in param:
                        param_required = param['required']

                    param_schemas = {}
                    if 'schema' in param:
                        param_schemas['*/*'] = param['schema']
                    # If content is in parameter, it will have very complex content and potentially multiple schemas
                    elif 'content' in param:
                        for mimetype in param['content'].keys():
                            param_schemas[mimetype] = param['content'][mimetype]['schema']

                    params_endpoint.append(Parameter(param['name'], param['in'], required=param_required, schemas=param_schemas))

            mthds = {}

            for method in paths[endpoint].keys():
                # Operation params can override endpoint params
                params_operation = []
                responses_operation = []

                method_object = paths[endpoint][method]

                # Openapi V2 and V3 may provide API-wide unique operation id for method
                method_unique_id = None

                if 'operationId' in method_object.keys():
                    method_unique_id = method_object['operationId']

                # Parameters of method
                if 'parameters' in method_object.keys():
                    # Common parameters for endpoint exists
                    for param in method_object['parameters']:
                        param_required = False
                        param_schemas = {}

                        # Use schemas for OA v3 and schema for OA v2
                        if 'required' in param:
                            param_required = param['required']

                        # OA V2 only 1 schema available and parameter is always in body

                        # Parameter can have only one schema

                        # Schema is in parameter which means it has only one schema
                        if 'schema' in param:
                            param_schemas['*/*'] = param['schema']
                        # If content is in parameter, it will have very complex content and potentially multiple schemas
                        elif 'content' in param:
                            for mimetype in param['content'].keys():
                                param_schemas[mimetype] = param['content'][mimetype]['schema']

                        params_operation.append(Parameter(param['name'], param['in'],
                                                          required=param_required,
                                                          schemas=param_schemas))

                # Handle OA V3 requestbody as simple body parameter
                if 'requestBody' in method_object.keys():
                    param_schemas = {}
                    for media_type, media_object in method_object['requestBody']['content'].items():
                        if 'schema' in media_object:
                            param_schemas[media_type] = media_object['schema']

                    # Request body may be required or not, defaults to not (according to OA V3 spec)
                    param_required = False
                    if 'required' in method_object['requestBody']:
                        if method_object['requestBody']['required']:
                            param_required = True

                    # This is named as requestbody, but treated as body in analysis
                    params_operation.append(Parameter("requestBody", "body",
                                                      required=param_required,
                                                      schemas=param_schemas))

                # Responses of method
                for code in method_object['responses'].keys():
                    # Make multiple schema handling to be similar than in request schemas
                    response_schemas = {}
                    if 'schema' in method_object['responses'][code].keys():
                        # OpenAPI V2, only 1 schema present
                        response_schemas['*/*'] =  method_object['responses'][code]['schema']

                    elif 'content' in method_object['responses'][code].keys():
                        # Openapi V3, possibly multiple schemas present
                        for media_type, media_object in method_object['responses'][code]['content'].items():
                            if 'schema' in media_object:
                                response_schemas[media_type] = media_object['schema']

                    responses_operation.append(Response(code, schemas=response_schemas))

                # Endpoint parameters are parsed to operation level (singlemethod)

                # Add here only params which are not duplicate (overriden endpoint params are dropped)
                params_final = []

                # Add endpoint parameters to final parameters if those are not overriden in method
                for p_e in params_endpoint:
                    if not any(p_o.name == p_e for p_o in params_operation):
                        params_final.append(p_e)

                # Add all operation parameters to final array
                params_final.extend(params_operation)

                # Input responses and parameters to single method
                mthds[method] = SingleMethod(method, endpoint, method_unique_id, params_final, responses_operation)

            # Create endpoint with list of method objects
            self.endpoints[endpoint] = (Endpoint(endpoint, mthds, server_address=self.server_address, basepath=self.server_basepath))

    def preprocess_har_entries(self):
        # Classify and filter out har entries to correct endpoints to wait for analysis

        # Determine if any endpoint matches to har entry url and add entry to endpoint if match is found

        # Pages field is optional in har specification
        # But Haralyzer promises to handle this situation by creating "fake page" which contains all such entries
        # So this code should work anyway

        # INFO: Haralyzer breaks if har file does not have pages field but works if it has empty pages field
        # Always have to take care of har file containing empty array in field "pages"

        for page in self.harobject.pages:
            for entry in page.entries:
                self.total_har_entries = self.total_har_entries + 1
                url = entry['request']['url']
                endpoint_found = False

                # First round of matching with no path parameters used
                for endpoint in self.endpoints.keys():
                    if self.endpoints[endpoint].match_url_to_path(url, use_path_parameters=False):
                        self.endpoints[endpoint].input_log_entry(entry)
                        endpoint_found = True
                        self.total_api_usages = self.total_api_usages + 1
                        break

                if not endpoint_found:
                    # Second round of matching with path parameters available if not found on first round
                    for endpoint in self.endpoints.keys():
                        if self.endpoints[endpoint].match_url_to_path(url):
                            self.endpoints[endpoint].input_log_entry(entry)
                            endpoint_found = True
                            self.total_api_usages = self.total_api_usages + 1
                            break

                # Print notification and add url to list of filtered out urls
                if not endpoint_found:
                    print(f"HAR entry URL {url} does not correspond any endpoint in API specification")
                    self.har_filtered_out_request_urls.append(url)

    def analyze(self):
        # May need heavy refactoring because also dict shows same data, could be combined

        # Trigger every endpoint analysis
        for endpoint in self.endpoints.keys():
            self.endpoints[endpoint].analyze_endpoint()

            # Collect info from endpoint after it has been analyzed
            self.total_response_codes_count += self.endpoints[endpoint].response_codes_in_methods_count
            self.total_response_codes_used += self.endpoints[endpoint].response_codes_in_methods_used

            self.total_default_responses_count += self.endpoints[endpoint].default_response_codes_in_methods_count
            self.total_default_responses_used += self.endpoints[endpoint].default_response_codes_in_methods_used

            self.total_methods_in_endpoints_count += self.endpoints[endpoint].methods_count
            self.total_methods_in_endpoints_used += self.endpoints[endpoint].methods_used

            self.total_parameters_count += self.endpoints[endpoint].parameters_in_methods_count
            self.total_parameters_used += self.endpoints[endpoint].parameters_in_methods_used

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

    def export_large_report_json(self, filename):
        # Exports json report
        # Currently just dumping that output dictionary to json file
        # Consider making json schema of report if needed
        all_data = self.get_all_report_data_as_dictionary()

        with open(filename, 'w') as f:
            json.dump(all_data, f)

    def analyze_coverage(self):
        '''
        Checks if given coverage level is fullfilled
        Save and return failures if it is not fullfilled
        If failures exist, return true, otherwise false in order to main function to crash program
        :return:
        '''

        if self.coverage_level_required == ApiCoverageLevel.COVERAGE_DISABLED:
            # Failure analysis and failure report is not made at all
            pass
        if self.coverage_level_required == ApiCoverageLevel.COVERAGE_ENDPOINT:
            # Check endpoint coverage
            for endpoint in self.endpoints.keys():
                # Skip excluded endpoints
                if endpoint in self.endpoints_excluded:
                    continue

                if not self.endpoints[endpoint].is_used():
                    self.coverage_requirement_passed = False
                    # Add failure and reason
                    self.coverage_level_failure_reasons.append(f"Endpoint {endpoint} is not used")

        if self.coverage_level_required == ApiCoverageLevel.COVERAGE_METHOD:
            # Check method coverage
            for endpoint in self.endpoints.keys():
                # Skip excluded endpoints
                if endpoint in self.endpoints_excluded:
                    continue

                if len(self.endpoints[endpoint].get_methods_not_used()) > 0:
                    self.coverage_requirement_passed = False
                    for mtd in self.endpoints[endpoint].get_methods_not_used():
                        self.coverage_level_failure_reasons.append(f"Endpoint's {endpoint} method {mtd} is not used")

        if self.coverage_level_required == ApiCoverageLevel.COVERAGE_RESPONSE:
            # Check response coverage
            for endpoint in self.endpoints.keys():
                # Skip excluded endpoints
                if endpoint in self.endpoints_excluded:
                    continue

                for mtd in self.endpoints[endpoint].methods.keys():
                    responses_not_used = self.endpoints[endpoint].methods[mtd].get_responses_not_used()
                    for resp in responses_not_used:
                        # If default response is treated like others, also it will cause coverage error
                        if not self.coverage_default_response_as_normal_response and resp == 'default':
                            continue
                        self.coverage_requirement_passed = False
                        self.coverage_level_failure_reasons.append(f"Endpoint's {endpoint} method {mtd} response {resp} is not used")

        if self.parameter_coverage_level_required in [ParameterCoverageLevel.COVERAGE_USED_ONCE, ParameterCoverageLevel.COVERAGE_USED_TWICE_UNIQUELY]:
            # Check parameter coverage
            # Every mentioned api parameter must be used once
            # Future issue could be definition of parameter exclusion in coverage

            for endpoint in self.endpoints.keys():
                # Skip excluded endpoints
                if endpoint in self.endpoints_excluded:
                    continue

                for mtd in self.endpoints[endpoint].methods.keys():
                    for param in self.endpoints[endpoint].methods[mtd].parameters:
                        if self.parameter_coverage_level_required == ParameterCoverageLevel.COVERAGE_USED_ONCE:
                            if param.usage_count == 0:
                                self.coverage_requirement_passed = False
                                self.coverage_level_failure_reasons.append(f"Endpoint's {endpoint} method's' {mtd} parameter {param.name} not used")
                        elif self.parameter_coverage_level_required == ParameterCoverageLevel.COVERAGE_USED_TWICE_UNIQUELY:
                            if len(param.unique_values) < 2:
                                self.coverage_requirement_passed = False
                                self.coverage_level_failure_reasons.append(f"Endpoint's {endpoint} method's' {mtd} parameter {param.name} used uniquely {len(param.unique_values)} times. 2 unique usages required to fullfill this coverage requirement")

    def export_coverage_failure_report(self, failure_report_filename):
        '''
        Saves the failure report to specified filename
        Name of the file is specified by command line arg failurereportname
        Overwrites file if same name exists
        Creates empty file if no failure report exist
        :return:
        '''

        # Keeping failure report as minimal as possible for now
        with open(failure_report_filename, 'w') as file:
            for fail in self.coverage_level_failure_reasons:
                file.write(fail + "\n")

    def analyze_anomalies(self):
        '''
        Analyze anomalies and save all anomalies and separate critical ones
        '''

        # Collect all anomalies
        for endpoint in self.endpoints.keys():
            # Check endpoint anomalies
            for endpoint_anomaly in self.endpoints[endpoint].anomalies:
                place_of_occurrence = f"Endpoint {endpoint}"
                self.anomalies_all.append((endpoint_anomaly, place_of_occurrence))

            # Check anomalies in endpoints method
            for method in self.endpoints[endpoint].methods.keys():
                place_of_occurrence = f"Endpoint {endpoint} - method {method.upper()}"
                for anomaly in self.endpoints[endpoint].methods[method].anomalies:
                    self.anomalies_all.append((anomaly, place_of_occurrence))

        # Append any critical anomaly to critical anomaly list
        for anomaly, place in self.anomalies_all:
            if anomaly.type in self.anomaly_types_causing_crash:
                self.anomalies_critical.append((anomaly, place))
                self.anomaly_requirements_passed = False

    def export_anomalies_report(self, critical_anomaly_report_filename, anomaly_report_filename):
        '''
        Export anomalies reports
        '''

        # Critical anomaly report
        with open(critical_anomaly_report_filename, 'w') as file:
            for anomaly, place_of_anomaly in self.anomalies_critical:
                file.write(place_of_anomaly + "\n")
                file.write("Given unique id for anomaly: " + str(anomaly.unique_id) + "\n")
                file.write(anomaly.description + "\n")
                file.write(str(anomaly.entry) + "\n\n")

        # All anomalies report

        # Translate data to dict representation before sorting and feeding to file template
        all_anomalies_as_dict = []

        for anomaly, place in self.anomalies_all:
            all_anomalies_as_dict.append((anomaly.get_as_dictionary(), place))

        # Sort by 2 different ways
        anomalies_sorted_by_category = sorted(all_anomalies_as_dict, key=lambda x: x[0]['type'])
        anomalies_sorted_by_endpoint = sorted(all_anomalies_as_dict, key=lambda x: x[1])

        env = Environment(
            loader=FileSystemLoader(PATH_TO_TEMPLATES_DIRECTORY)
        )

        template = env.get_template('anomaly_report.txt')

        template.stream(anomalies_sorted_by_category=anomalies_sorted_by_category,
                        anomalies_sorted_by_endpoint=anomalies_sorted_by_endpoint).dump(anomaly_report_filename)

    def get_all_report_data_as_dictionary(self):

        all_data_dictionary = {
           'open_api_version': self.open_api_version,
           'api_name': self.api_name,
           'api_description': self.api_description,
           'api_version': self.api_version,
           'total_api_usages': self.total_api_usages,
           'total_har_entries': self.total_har_entries,
           'har_filtered_out_request_urls': self.har_filtered_out_request_urls,
           'analysis_initiation_time': self.analysis_initiated,
           'endpoints': [],
           'total_endpoints_count': self.endpoints_count,
           'total_endpoints_used': self.endpoints_used,
           'total_response_codes_count': self.total_response_codes_count,
           'total_response_codes_used': self.total_response_codes_used,
           'total_default_responses_count': self.total_default_responses_count,
           'total_default_responses_used': self.total_default_responses_used,
           'total_methods_in_endpoints_count': self.total_methods_in_endpoints_count,
           'total_methods_in_endpoints_used': self.total_methods_in_endpoints_used,
            'total_parameters_count': self.total_parameters_count,
            'total_parameters_used': self.total_parameters_used
        }

        endpoint_dictionaries = []

        for e in self.endpoints:
            endpoint_dictionaries.append(self.endpoints[e].get_as_dictionary())

        all_data_dictionary['endpoints'] = endpoint_dictionaries

        return all_data_dictionary

    def export_large_report_text(self, filename):
        all_data = self.get_all_report_data_as_dictionary()

        env = Environment(
            loader=FileSystemLoader(PATH_TO_TEMPLATES_DIRECTORY)
        )

        template = env.get_template('large_report.txt')

        template.stream(data=all_data).dump(filename)

    def crash_program(self, crash_on_critical_failure=True):
        # Crash program with exit code 1 if needed and not suppressed
        # This intends to serve Jenkins or other CI tool purposes to indicate that testing is not good enough
        if crash_on_critical_failure and (not self.coverage_requirement_passed or not self.anomaly_requirements_passed):
            # Crash program
            exit(1)


def main():
    # Use configuration file instead of command line because different settings are starting to be too complex
    parser = argparse.ArgumentParser(description='Calculate API spec coverage from HAR files and API spec')
    parser.add_argument('apispec', help='Api specification file')
    parser.add_argument('harfile', help='Captured traffic in HAR file format')
    parser.add_argument("--cf", help="Configuration file", default="config.ini")

    # Making possible to override couple of more used things from command line
    parser.add_argument("--serveraddress", help="Address of the server. Overrides value from config file")
    parser.add_argument("--basepath", help="Basepath to be appended to serveraddress. Overrides value from config file")

    args = parser.parse_args()

    # Get config parser
    config = configparser.ConfigParser()
    config.read(args.cf)

    # Get coverage level, default in broken config situation is disabled coverage analysis
    api_coverage_level = ApiCoverageLevel[config.get('COVERAGE', 'api_coverage_level', fallback="COVERAGE_DISABLED")]

    # Get wheter default response code is treated as other codes in coverage calculations
    api_coverage_default_response_as_normal_response = config.getboolean('COVERAGE', 'default_response_as_normal', fallback=False)

    # Get parameter coverage level, if not specified, parameter coverage will be disabled
    parameter_coverage_level = ParameterCoverageLevel[config.get('COVERAGE', 'parameter_coverage_level', fallback="COVERAGE_DISABLED")]

    # Get and parse list of anomalies which will cause error
    critical_anomalies_config = config.get('CRITICAL_ANOMALIES', 'critical_anomalies', fallback="")
    critical_anomalies = []

    for ca in critical_anomalies_config.split(','):
        critical_anomalies.append(AnomalyType[ca])

    # Get misc settings
    crash_in_critical_failure = config.getboolean('MISC', 'crash_in_critical_failure', fallback=True)
    suppress_console_anomalies_output = config.getboolean('MISC', 'suppress_console_anomalies_output', fallback=False)

    # Get and parse list of endpoints which will be excluded from coverage analysis
    exclude_endpoints_config = config.get('EXCLUSIONS', 'exclude_endpoints', fallback="")
    exclude_endpoints = []

    for ee in exclude_endpoints_config.split(','):
        exclude_endpoints.append(ee)

    # Get server and basepath from configuration file
    # If not found, empty string should be default
    server_serveraddress = config.get('SERVER_AND_BASEPATH', 'serveraddress', fallback="")
    server_basepath = config.get('SERVER_AND_BASEPATH', 'basepath', fallback="")

    # Get filenamesnames for reports from configuration file
    filename_coverage_failure = config.get('FILE_PATHS', 'report_filename_coverage_failure_report', fallback='coverage_failure_report.txt')
    filename_anomaly_failure = config.get('FILE_PATHS', 'report_filename_anomaly_failure_report', fallback='anomaly_failure_report.txt')
    filename_anomaly = config.get('FILE_PATHS', 'report_filename_anomaly_report', fallback='anomaly_report.txt')
    filename_large_txt = config.get('FILE_PATHS', 'report_filename_large_report_txt', fallback='large_report_text.txt')
    filename_large_json = config.get('FILE_PATHS', 'report_filename_large_report_json', fallback='large_report_json.json')

    # Override serveraddress if given
    if args.serveraddress is not None:
        server_serveraddress = args.serveraddress

    # Override basepath if given
    if args.basepath is not None:
        server_basepath = args.basepath

    asc = ASC(args.apispec, args.harfile,
              coverage_level_required=api_coverage_level,
              endpoints_excluded=exclude_endpoints,
              parameter_coverage_level_required=parameter_coverage_level,
              coverage_level_default_response_as_normal_code=api_coverage_default_response_as_normal_response,
              anomaly_types_causing_crash=critical_anomalies,
              server_address=server_serveraddress,
              server_basepath=server_basepath)

    asc.read_api_specification()
    asc.read_har_file()
    asc.preprocess_har_entries()
    asc.analyze()
    asc.print_analysis_to_console(suppress_console_anomalies_output)

    asc.analyze_coverage()
    asc.export_coverage_failure_report(filename_coverage_failure)

    asc.analyze_anomalies()
    asc.export_anomalies_report(filename_anomaly_failure, filename_anomaly)

    asc.export_large_report_text(filename_large_txt)
    asc.export_large_report_json(filename_large_json)

    asc.crash_program(crash_on_critical_failure=crash_in_critical_failure)


if __name__ == '__main__':
    main()
