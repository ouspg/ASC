import re
from urllib.parse import urlparse
# Colors from here https://svn.blender.org/svnroot/bf-blender/trunk/blender/build_files/scons/tools/bcolors.py


class TerminalColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


def path_parameter_extractor(url, path, parameter_name):

    url_path = urlparse(url).path

    if path.find('{' + parameter_name + '}') != -1:
        # Cut path until wanted parameter
        path_prepart = path.split('{' + parameter_name + '}')[0]

        # Replace path parameters in prepath with no-slash wildcard
        path_prepart = re.sub('{.+?}', '[^/]+', path_prepart)

        result = re.search(path_prepart + '(?P<path_parameter_value>.+?(?=/|$))', url_path)

        # If no match, then return empty value
        if result is None:
            return ""

        return result.group('path_parameter_value')

    else:
        # Parameter name does not exist at all in path string
        return ""


# TODO: write couple of unit tests for this
# TODO: Should work for now, but needing parsing for more complex schema side mimetypes in future
def find_best_mimetype_match_for_content_header(list_of_possible_mimetypes, content_header_string):
    # First, try to find straight match
    for singlefield in content_header_string.split(';'):
        # Explicit match found
        if singlefield in list_of_possible_mimetypes:
            return singlefield

    # If explicit match not found, trying to look for match with wildcard

    for possible_mimetype in list_of_possible_mimetypes:
        # Look only for half-wildcard mimetypes
        if '/*' in possible_mimetype and '*/*' not in possible_mimetype:
            for singlefield in content_header_string.split(';'):
                # Check if start of header mimetype is same than possible semi-wildcard mimetype
                if (singlefield.split('/')[0] + '/*') == possible_mimetype:
                    return possible_mimetype

    # No good matches found, so must use general match '*/*' if it exists
    if '*/*' in list_of_possible_mimetypes:
        return '*/*'

    # No matches found
    return False
