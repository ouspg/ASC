import json
from haralyzer import HarParser, HarPage
import re
import argparse
from argparse_utils import enum_action
import copy
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

from utils import TerminalColors, get_multipart_boundary, decode_multipart, path_parameter_extractor, find_best_mimetype_match_for_content_header


class Endpoint:
    def __init__(self, path, methods, baseurl="", excluded=False):
        self.path = path
        self.methods = methods
        # Baseurl needed to eliminate changes for some weird urls in har to map incorrectly
        # Should also server url be specified?
        self.baseurl = baseurl
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

        # Currently endpoint level parameters are dropped to operation level (singlemethod) during parsing
        # Operation level can override endpoint parameters, so it feels locically to handle those always there
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

        # Is basepath needed at all? end of url is the part which is compared anyway
        # if server name remains most likely irrelevant this should not be problem
        # And if weird special cases can be tolerated, this should be ok
        # url.parsed.path, problem with endswith might be that it might match to something else too
        # Like alsdkfj/aksldfj/pet to /pet

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
            'response_codes_in_methods_count': self.response_codes_in_methods_count,
            'response_codes_in_methods_used': self.response_codes_in_methods_used,
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
        # TODO: methot info never used... consider it again
        self.methodinfo = methodinfo

        # TODO: Add operation id, as it is also unique identifier if it is present

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
                    # TODO: Check if it even in theory possible that path parameter has schema
                    # Yes, in oa v3 is possible but in 2 maybe not
                    # Use new utility function now
                    paramvalue = path_parameter_extractor(url, self.path, param.name)

                    # Path parameter can not be empty
                    param.add_usage(paramvalue)

                elif param.location == 'query':
                    # TODO: Check if schema exists, and then validate parameter against it, otherwise do nothing
                    #  Do same to other param types and possibly refactor this whole loop
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
                    paramvalue = entry['request']['postData']['text']
                    param.add_usage(paramvalue)

                    # Check for empty body, because body parameter or requestbody parameter can be not required too
                    if (paramvalue == '') and param.required:
                        # Add anomaly for missing body if it is required
                        self.anomalies.append(
                            Anomaly(entry, AnomalyType.MISSING_REQUIRED_REQUEST_PARAMETER,
                                    "Required parameter " + str(
                                        param.name) + " was not found in request body"
                                    ))
                    else:
                        # Add body parameter usage
                        param.add_usage(paramvalue)

                    # TODO: Should jump out if body is missing?

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

                        # TODO: Body should have at least schema object
                        #  Consider making anomaly if schema is not found in spec and do not continue body analysis

                        # Schema selection code
                        selected_schema = find_best_mimetype_match_for_content_header(param.schemas.keys(), postdata_mimetype)

                        # If there was no schema
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
                        # Parse multipart data from response with custom functions

                        # TODO: Getting boundary and parsed data are so tightly connected that consider combining
                        # Have to make own decoder because requests_toolbelt.MultipartDecoder does not work!
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
                        resp.add_usage(entry['response']['content']['text'])

                        # Currently only limited json body validation is supported

                        response_mimetype = entry['response']['content']['mimeType']

                        # TODO: Check that there is schema in first place
                        #  It is possible in oa v2 that schema does simply exist in response body

                        # Schema selection for analysis
                        selected_schema = find_best_mimetype_match_for_content_header(resp.schemas.keys(),
                                                                                      response_mimetype)
                        # If there was no schema
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


class AnomalyType(Enum):
    UNDEFINED_RESPONSE_CODE_DEFAULT_NOT_SPECIFIED = 1
    MISSING_REQUIRED_REQUEST_PARAMETER = 2
    BROKEN_REQUEST_BODY = 3
    UNDEFINED_RESPONSE_CODE_DEFAULT_IS_SPECIFIED = 4
    BROKEN_RESPONSE_BODY = 5
    DEFAULT_RESPONSE_IS_NOT_USED = 6
    INVALID_RESPONSE_BODY = 7
    UNDEFINED_METHOD_OF_ENDPOINT = 8
    UNMATCHED_REQUEST_BODY_MIMETYPE = 9
# TODO: Should also invalid request body be added because there is both in responses too
#  Consider validity of this anomaly approach
# TODO: Consider sensibility of next 2 anomalies UNDEFINED_RESPONSE_CODE_DEFAULT_IS_SPECIFIED DEFAULT_RESPONSE_IS_NOT_USED

class Anomaly:
    def __init__(self, entry, type, description):
        self.entry = entry
        self.type = type
        self.description = description

    def get_as_dictionary(self):
        anomaly_dictionary = {
            'entry': self.entry,
            'type': self.type.value,
            'description': self.description
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
                 parameter_coverage_level_required, anomaly_types_causing_crash):
        self.apispec_addr = apispec_addr
        self.har_addr = har_addr

        self.apispec = ""
        self.harobject = ""

        self.endpoints = {}
        self.basepath = ""

        self.endpoints_excluded = endpoints_excluded

        self.coverage_level_required = coverage_level_required
        self.parameter_coverage_level_required = parameter_coverage_level_required

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

    def read_har_file(self):
        # Initialize har parser object
        with open(self.har_addr, 'r') as f:
            self.harobject = HarParser(json.loads(f.read()))

    def read_api_specification(self):
        # Parse API spec to endpoint and method objects with prance parser

        # NOTICE: OA v2 seems to be working fine with openapi spec validator and swagger validator too
        # NOTICE: Json seems to be working always, but some cases yaml fails (problem with strings?)
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

                # Parameters of method
                if 'parameters' in paths[endpoint][method].keys():
                    # Common parameters for endpoint exists
                    for param in paths[endpoint][method]['parameters']:
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
                if 'requestBody' in paths[endpoint][method].keys():
                    param_schemas = {}
                    for media_type, media_object in paths[endpoint][method]['requestBody']['content'].items():
                        if 'schema' in media_object:
                            param_schemas[media_type] = media_object['schema']

                    # Request body may be required or not, defaults to not (according to OA V3 spec)
                    param_required = False
                    if 'required' in paths[endpoint][method]['requestBody']:
                        if paths[endpoint][method]['requestBody']['required']:
                            param_required = True

                    # This is named as requestbody, but treated as body in analysis
                    params_operation.append(Parameter("requestBody", "body",
                                                      required=param_required,
                                                      schemas=param_schemas))

                # Responses of method
                for code in paths[endpoint][method]['responses'].keys():
                    # Make multiple schema handling to be similar than in request schemas
                    response_schemas = {}
                    if 'schema' in paths[endpoint][method]['responses'][code].keys():
                        # OpenAPI V2, only 1 schema present
                        response_schemas['*/*'] = paths[endpoint][method]['responses'][code]['schema']

                    elif 'content' in paths[endpoint][method]['responses'][code].keys():
                        # Openapi V3, possibly multiple schemas present
                        for media_type, media_object in paths[endpoint][method]['responses'][code]['content'].items():
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

                # Print notification and add url to list of filtered out urls
                if not endpoint_found:
                    print(f"HAR entry URL {url} does not correspond any endpoint in API specification")
                    self.har_filtered_out_request_urls.append(url)

    def analyze(self):
        # Trigger every endppoint analysis
        for endpoint in self.endpoints.keys():
            self.endpoints[endpoint].analyze_endpoint()

            # Collect info from endpoint after it has been analyzed
            self.total_response_codes_count += self.endpoints[endpoint].response_codes_in_methods_count
            self.total_response_codes_used += self.endpoints[endpoint].response_codes_in_methods_used

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
        # Coverage based on given level to determine if failed or not and failure reasons as string array
        coverage_level_fulfilled = True
        coverage_level_failure_reasons = []

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
                    coverage_level_fulfilled = False
                    # Add failure and reason
                    coverage_level_failure_reasons.append(f"Endpoint {endpoint} is not used")

        if self.coverage_level_required == ApiCoverageLevel.COVERAGE_METHOD:
            # Check method coverage
            for endpoint in self.endpoints.keys():
                # Skip excluded endpoints
                if endpoint in self.endpoints_excluded:
                    continue

                if len(self.endpoints[endpoint].get_methods_not_used()) > 0:
                    coverage_level_fulfilled = False
                    for mtd in self.endpoints[endpoint].get_methods_not_used():
                        coverage_level_failure_reasons.append(f"Endpoint's {endpoint} method {mtd} is not used")

        if self.coverage_level_required == ApiCoverageLevel.COVERAGE_RESPONSE:
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
                                coverage_level_fulfilled = False
                                coverage_level_failure_reasons.append(f"Endpoint's {endpoint} method's' {mtd} parameter {param.name} not used")
                        elif self.parameter_coverage_level_required == ParameterCoverageLevel.COVERAGE_USED_TWICE_UNIQUELY:
                            if len(param.unique_values) < 2:
                                coverage_level_fulfilled = False
                                coverage_level_failure_reasons.append(f"Endpoint's {endpoint} method's' {mtd} parameter {param.name} used uniquely {len(param.unique_values)} times. 2 unique usages required to fullfill this coverage requirement")

        return coverage_level_fulfilled, coverage_level_failure_reasons

    def analyze_and_export_coverage_failure_report(self, failure_report_filename):
        '''
        Saves the failure report to specified filename
        Name of the file is specified by command line arg failurereportname
        Overwrites file if same name exists
        Creates empty file if no failure report exist
        :return:
        '''

        coverage_level_achieved, failures = self.analyze_coverage()

        self.coverage_requirement_passed = coverage_level_achieved

        # Keeping failure report as minimal as possible for now
        with open(failure_report_filename, 'w') as file:
            for fail in failures:
                file.write(fail + "\n")

    def analyze_and_export_anomaly_report(self, anomaly_report_filename, critical_anomaly_report_filename):
        '''
        :param anomaly_report_filename:
        Creates report listing only anomalies
        Anomalies categorized under each endpoint and type
        If crashing anomaly is found, write those to separate file and crash the program later
        :return:
        '''
        # For now use simple text file for failure report
        with open(critical_anomaly_report_filename, 'w') as file:
            for endpoint in self.endpoints.keys():
                # Check endpoint anomalies
                for endpoint_anomaly in self.endpoints[endpoint].anomalies:
                    if endpoint_anomaly.type in self.anomaly_types_causing_crash:
                        # Critical failure anomaly encountered
                        file.write(endpoint_anomaly.description + "\n")
                        file.write(str(endpoint_anomaly.entry) + "\n")
                        self.anomaly_requirements_passed = False

                # Check anomalies in endpoints method
                for method in self.endpoints[endpoint].methods.keys():
                    for anomaly in self.endpoints[endpoint].methods[method].anomalies:
                        if anomaly.type in self.anomaly_types_causing_crash:
                            # Critical failure anomaly encountered
                            file.write(anomaly.description + "\n")
                            file.write(str(anomaly.entry) + "\n")
                            self.anomaly_requirements_passed = False

        # Use more complex template for larger anomaly report
        # All anomalies as tuple (Anomaly, place_of_occurrence)
        anomalies_all = []

        for endpoint in self.endpoints.keys():
            for method in self.endpoints[endpoint].methods.keys():
                for anomaly in self.endpoints[endpoint].methods[method].anomalies:
                    place_of_occurrence = f"Endpoint {endpoint} - method {method.upper()}"
                    anomalies_all.append((anomaly.get_as_dictionary(), place_of_occurrence))

            for anomaly in self.endpoints[endpoint].anomalies:
                place_of_occurrence = f"Endpoint {endpoint}"
                anomalies_all.append((anomaly.get_as_dictionary(), place_of_occurrence))

        anomalies_sorted_by_category = sorted(anomalies_all, key=lambda x: x[0]['type'])
        anomalies_sorted_by_endpoint = sorted(anomalies_all, key=lambda x: x[1])

        env = Environment(
            loader=FileSystemLoader('Templates/')
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
           'total_methods_in_endpoints_used': self.total_methods_in_endpoints_used
        }

        endpoint_dictionaries = []

        for e in self.endpoints:
            endpoint_dictionaries.append(self.endpoints[e].get_as_dictionary())

        all_data_dictionary['endpoints'] = endpoint_dictionaries

        return all_data_dictionary

    def export_large_report_text(self, filename):
        all_data = self.get_all_report_data_as_dictionary()

        # print(json.dumps(self.get_all_report_data_as_dictionary(), sort_keys=True, indent=4))

        env = Environment(
           loader=FileSystemLoader('Templates/')
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

    args = parser.parse_args()

    # Get config parser
    config = configparser.ConfigParser()
    config.read(args.cf)

    # Get coverage level, default in broken config situation is disabled coverage analysis
    api_coverage_level = ApiCoverageLevel[config.get('COVERAGE', 'api_coverage_level', fallback="COVERAGE_DISABLED")]

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

    asc = ASC(args.apispec, args.harfile,
              coverage_level_required=api_coverage_level,
              endpoints_excluded=exclude_endpoints,
              parameter_coverage_level_required=parameter_coverage_level,
              anomaly_types_causing_crash=critical_anomalies)

    asc.read_api_specification()
    asc.read_har_file()
    asc.preprocess_har_entries()
    asc.analyze()
    asc.print_analysis_to_console(suppress_console_anomalies_output)
    asc.analyze_and_export_coverage_failure_report(config['FILE_PATHS']['report_filename_coverage_failure_report'])
    asc.analyze_and_export_anomaly_report(config['FILE_PATHS']['report_filename_anomaly_failure_report'],
                                          config['FILE_PATHS']['report_filename_anomaly_report'])
    asc.export_large_report_text(config['FILE_PATHS']['report_filename_large_report_txt'])
    asc.export_large_report_json(config['FILE_PATHS']['report_filename_large_report_json'])

    asc.crash_program(crash_on_critical_failure=crash_in_critical_failure)


if __name__ == '__main__':
    main()