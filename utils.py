import re

# Colors from here https://svn.blender.org/svnroot/bf-blender/trunk/blender/build_files/scons/tools/bcolors.py


class TerminalColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


# TODO: consider that those 2 functions could be tied together somehow
def get_multipart_boundary(req_entry):
    for header in req_entry['headers']:
        if header['name'] == 'content-type':
            boundarysearch = re.search('boundary=(.*?)( |$)', header['value'])
            boundvalue = boundarysearch.group(1)
            return boundvalue


# TODO: Improve readibility and write exhaustive testing and inspect multipart decoder to make your own
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

    return parsed_items


def path_parameter_extractor(url, path, parameter_name):

    if path.find('{' + parameter_name + '}') != -1:
        path_prepart = path.split('{' + parameter_name + '}')[0]

        # If second part exists

        # Replace path parameters in prepath with no-slash wildcard
        path_prepart = re.sub('{.+?}', '[^/]+', path_prepart)

        # TODO: Basic testing done, do couple more special cases
        result = re.search(path_prepart + '(?P<path_parameter_value>.+?(?=/|$))', url)

        # If no match, then return empty value
        if result is None:
            return ""

        return result.group('path_parameter_value')

    else:
        # Parameter name does not exist at all in path string
        return ""
