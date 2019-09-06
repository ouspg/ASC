# ASC - API Specification Coverage tool

## Main description

This API Spec Coverage tool is meant to be be used to show how much of API is covered by test run by inspecting captured HAR files. Program also tries to detect any anomalies in traffic by validating requests/reponses against API specification.

Major features are in place, but refactoring and testing is WIP.

Program takes 3 inputs: OpenAPI Specification (version 2 or 3), captured traffic during test run (HAR file) and configuration file (default name `config.ini`).

* OpenAPI specification file is .yaml or .json file describing OpenAPI [OpenAPI V2](https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md) or [OpenAPI V3](https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.2.md)

* HAR file is capture traffic file following [HAR 1.2 specification](http://www.softwareishard.com/blog/har-12-spec/)

* Configuration file is standard ini-file which defines more accurately in which cases program will produce 1 as exit code (which hopefully helps this program usage as CI/CD pipeline). Also other program parameters can be defined there, like output file locations.

Program outputs multiple files:
* Program will always produce large textual and json reports about API specification usage and list of all anomalies encountered
* If coverage requirement and/or anomalies which will cause critical failures are encountered, program will output text files describing those errors correnspondingly


## Example runs

You may run analysis with example files in this repository like next: `python3 ASC.py petstore_v3.json petstore_v3_har.har` or `python3 ASC.py petstore_v2.json petstore_v2_har.har`

## How to make your own testing

Most fastest way may be next:

* Find some web browser client which makes calls to some OpenAPI API
* Open developer tools network tab on your browser and start clicking around client
* Use "Save as HAR" feature on network tab
* Input OpenAPI specification and har file to API Specification Coverage tool
* See the analysis how the api was used during your browser usage