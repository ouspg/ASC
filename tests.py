from unittest import TestCase

from ASC_v2 import Endpoint


class EndpointMatchUrlToPathCases(TestCase):
    '''
    Testing Endpoint-class URL to patch matching function
    '''

    @classmethod
    def setUpClass(cls):
        cls.testendpoint1 = Endpoint('/pet/somestaticendpoint', [], "localhost/v3")

        cls.testendpoint2 = Endpoint('/pet/somestaticthing/{petId}', [], "localhost/v3")

    @classmethod
    def tearDownClass(cls):
        cls.testendpoint1 = None

    def test_nopath_params(self):
        trueurls = [
            'http://localhost/v3/pet/somestaticendpoint',
            'http://localhost/v3/pet/somestaticendpoint/',
            'http://localhost//v3/pet//somestaticendpoint'
        ]

        falseurls = [
            'http://localhost/v3/pet/somestaticendpoint/somestaticendpoint///localhost/v3/pet/somestaticendpoint/somestaticendpoint',
            'http://localhost/v3/pet/somestaticendpoint/888',
            'http://localhost/v3/pet/somestaticendpoint/somestaticendpoint',
            'http://localhost/v3/pet/somestaticendpoint/pet/somestaticendpoint',
            'http://localhost/v3/pet/pet/somestaticendpoint',
            'http://localhost/v3/pet/somestaticendpoint///localhost/v3/pet/somestaticendpoint'
        ]

        for expectrueurl in trueurls:
            with self.subTest(msg="Expecting true match", pattern=self.testendpoint1.path, url=expectrueurl):
                self.assertTrue(self.testendpoint1.match_url_to_path(expectrueurl))

        for expectfalseurl in falseurls:
            with self.subTest(msg="Expecting false match", pattern=self.testendpoint1.path, url=expectfalseurl):
                self.assertFalse(self.testendpoint1.match_url_to_path(expectfalseurl))

    def test_1_path_parameter(self):
        trueurls = [
            'http://localhost/v3/pet/somestaticthing/somestaticthing',
            'http://localhost/v3/pet/somestaticthing/98765',
            'http://localhost/v3/pet/somestaticthing/98765/',
            'https://localhost/v3///pet//somestaticthing//98765'
        ]

        falseurls = [
            'http://localhost/v3/pet/somestaticthing/somestaticthing///localhost/v3/pet/somestaticthing/somestaticthing',
            'http://localhost/v3/pet/somestaticthing/888/somestaticthing',
            'http://localhost/v3/pet/somestaticthing/',
            'http://localhost/v3/pet/somestaticthing',
            'http://localhost/v3/pet/pet/somestaticthing/888',
            'http://localhost/v3/pet/somestaticthing///localhost/v3/pet/somestaticthing/98765'
        ]

        for expectrueurl in trueurls:
            with self.subTest(msg="Expecting true match", pattern=self.testendpoint2.path, url=expectrueurl):
                self.assertTrue(self.testendpoint2.match_url_to_path(expectrueurl))

        for expectfalseurl in falseurls:
            with self.subTest(msg="Expecting false match", pattern=self.testendpoint2.path, url=expectfalseurl):
                self.assertFalse(self.testendpoint2.match_url_to_path(expectfalseurl))