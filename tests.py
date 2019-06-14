from unittest import TestCase

from ASC_v2 import Endpoint
from ASC_v2 import path_parameter_extractor


class EndpointMatchUrlToPathCases(TestCase):
    '''
    Testing Endpoint-class URL to patch matching function
    '''

    @classmethod
    def setUpClass(cls):
        cls.testendpoint1 = Endpoint('/pet/somestaticendpoint', [], "/v3")

        cls.testendpoint2 = Endpoint('/pet/somestaticthing/{petId}', [], "/v3")

        cls.testtendpoint3_1 = Endpoint('/pet/{ownerId}/{petId}', [], "/v3")
        cls.testtendpoint3_2 = Endpoint('/pet/{ownerId}/somestaticthing/{petId}', [], "/v3")

    @classmethod
    def tearDownClass(cls):
        cls.testendpoint1 = None

    def test_nopath_params(self):
        trueurls = [
            'http://localhost/v3/pet/somestaticendpoint',
            'http://localhost/v3/pet/somestaticendpoint/'
        ]

        # Leaving double slash test later if needed
        #
        # 'http://localhost//v3/pet//somestaticendpoint'

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
            'http://localhost/v3/pet/somestaticthing/98765/'
        ]

        # Leave out double slash tests for now
        # 'https://localhost/v3///pet//somestaticthing//98765'

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

    def test_2_path_parameter_set1(self):
        trueurls = [
            'http://localhost/v3/pet/someparameter/someotherparam',
            'http://localhost/v3/pet/0988765/98765',
            'http://localhost/v3/pet/somestaticthing/98765/'
        ]
        # Leave out double slash tests
        # 'https://localhost/v3///pet//somestaticthing//98765'

        falseurls = [
            'http://localhost/v3/pet/somestaticthing/somestaticthing///localhost/v3/pet/somestaticthing/some/somestaticthing',
            'http://localhost/v3/pet/somestaticthing/888/somestaticthing',
            'http://localhost/v3/pet/somestaticthing/',
            'http://localhost/v3/pet/somestaticthing',
            'http://localhost/v3/pet/pet/somestaticthing/888',
            'http://localhost/v3/pet/somestaticthing///localhost/v3/pet/somestaticthing/98765'
        ]

        for expectrueurl in trueurls:
            with self.subTest(msg="Expecting true match", pattern=self.testtendpoint3_1.path, url=expectrueurl):
                self.assertTrue(self.testtendpoint3_1.match_url_to_path(expectrueurl))


        for expectfalseurl in falseurls:
            with self.subTest(msg="Expecting false match", pattern=self.testtendpoint3_1.path, url=expectfalseurl):
                self.assertFalse(self.testtendpoint3_1.match_url_to_path(expectfalseurl))

    def test_2_path_parameter_set2(self):
        trueurls = [
            'http://localhost/v3/pet/someparameter/somestaticthing/somepathparam',
            'http://localhost/v3/pet/0988765/somestaticthing/0909',
            'http://localhost/v3/pet/88888/somestaticthing/98765/'
        ]
        # Leave out double slash tests
        # 'https://localhost/v3///pet//someparam//somestaticthing//98765'

        falseurls = [
            'http://localhost/v3/pet/somestaticthing/somestaticthing///localhost/v3/pet/somestaticthing/some/somestaticthing',
            'http://localhost/v3/pet/somestaticthing/888/somestaticthing',
            'http://localhost/v3/pet/somestaticthing/9898',
            'http://localhost/v3/pet/somestaticthing',
            'http://localhost/v3/pet/pet/somestaticthing/somestaticthing/888',
            'http://localhost/v3/pet/somestaticthing///localhost/v3/pet/somestaticthing/98765'
        ]

        for expectrueurl in trueurls:
            with self.subTest(msg="Expecting true match", pattern=self.testtendpoint3_2.path, url=expectrueurl):
                self.assertTrue(self.testtendpoint3_2.match_url_to_path(expectrueurl))


        for expectfalseurl in falseurls:
            with self.subTest(msg="Expecting false match", pattern=self.testtendpoint3_2.path, url=expectfalseurl):
                self.assertFalse(self.testtendpoint3_2.match_url_to_path(expectfalseurl))


class PathParameterExtractionTests(TestCase):
    '''
    Testing path_parameter_extractor utility funtion
    '''

    def setUp(self) -> None:
        pass

    def tearDown(self) -> None:
        pass

    def test_no_parameter_in_path(self):

        tests = [
            ("http://localhost/v3/pet/somestaticthing/", "/pet/somestaticthing/{petId}", "petId", ""),
            ("http://localhost/v3/pet/somestaticthing/999", "/pet/somestaticthing/{petId}", "notpetId", "")
        ]

        for test in tests:
            with self.subTest(msg="Empty parameter should be found", url=test[0], pattern=test[1], paramname=test[2]):
                self.assertEqual(path_parameter_extractor(test[0], test[1], test[2]), test[3])

    def test_1_path_parameter_set1(self):
        tests = [
            ("http://localhost/v3/pet/somestaticthing/999", "/pet/somestaticthing/{petId}", "petId", "999"),
            ("http://localhost/v3/pet/somestaticthing/asdf", "/pet/somestaticthing/{petId}", "petId", "asdf")
        ]

        for test in tests:
            with self.subTest(msg="Right parameter should be found", url=test[0], pattern=test[1], paramname=test[2]):
                self.assertEqual(path_parameter_extractor(test[0], test[1], test[2]), test[3])

    def test_1_path_parameter_set2(self):
        tests = [
            ("http://localhost/v3/pet/somestaticthing/999/someotheraction", "/pet/somestaticthing/{petId}/someotheraction", "petId", "999"),
            ("http://localhost/v3/pet/somestaticthing/asdf/pet", "/pet/somestaticthing/{petId}/pet", "petId", "asdf")
        ]

        for test in tests:
            with self.subTest(msg="Right parameter should be found", url=test[0], pattern=test[1], paramname=test[2]):
                self.assertEqual(path_parameter_extractor(test[0], test[1], test[2]), test[3])

    def test_2_path_parameters(self):
        tests = [
            ("http://localhost/v3/pet/somestaticthing/999/888", "/pet/somestaticthing/{petId}/{otherId}", "petId", "999"),
            ("http://localhost/v3/pet/somestaticthing/asdf/jkl", "/pet/somestaticthing/{petId}/{otherId}", "otherId", "jkl"),
            ("http://localhost/v3/pet/somestaticthing/asdf/otherstaticthing/jkl", "/pet/somestaticthing/{petId}/otherstaticthing/{otherId}", "otherId", "jkl"),
            ("http://localhost/v3/pet/somestaticthing/asdf/otherstaticthing/jkl",
             "/pet/somestaticthing/{petId}/otherstaticthing/{otherId}", "petId", "asdf")
        ]

        for test in tests:
            with self.subTest(msg="Right parameter should be found", url=test[0], pattern=test[1], paramname=test[2]):
                self.assertEqual(path_parameter_extractor(test[0], test[1], test[2]), test[3])