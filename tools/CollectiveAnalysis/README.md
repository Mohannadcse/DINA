CollectiveAnalysis
==================

CollectiveAnalysis performs static analysis for extracting intent filter information, reflection  and dynamic class loading from the apps in the bundle under the analysis.

## Running

The extracted information will be stored in the `output` directory after running CollectiveAnalysis.

### Analyzing Apps in a Directory

Assuming a directory `../../../apks` contains a set of APK files, run

    cd build/tools/CollectiveAnalysis
    ./launch --path ../../../apks
