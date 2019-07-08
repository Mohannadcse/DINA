IncrementalAnalysis
==================

IncrementalAnalysis performs incremental dynamic analsysis for executing reflection and dynamic class loading by installing and running the apps in the bundle under the analysis. We use Monkey for generating random user's activities and actions.

## Running

The extracted information will be stored in the `output` directory after running IncrementalAnalysis.

### Analyzing Apps in a Directory

Assuming a directory `../../../apks` contains a set of APK files, run

    cd build/tools/IncrementalAnalysis
    ./launch  ../../../apks
