# The SEPSES Cyber-KB Engine (v1.1.0)

This engine is designed as a RDF generation mechanism from several CyberSecurity resources.
In our server, we add additional bash command to run it continuously, but we didn't provide the script here.

To run this prototype, the prerequisite is that you have a JDK 8+ and Maven installed in your computer.
Additionally, the config.properties is build for local Jena fuseki installation. Make sure that: 
* the `config.properties` is available (and adjust it if necessary; especially with regards to the triplestore/fuseki installation)
* you have an empty repo called 'sepses' in your fuseki/virtuoso installation
    * you can also run it without storing the data to triplestore using "dummy" as storage
    * currently still need an active sparql endpoint (TODO: to fix this).

The following steps are required to run the engine: 
* run `mvn clean` to build the required jar files from the `lib` folder
* run `mvn install -DskipTests=true` to build the application
    * optionally, you can also run the tests (without the `-DskipTests=true`) to run checks of extracted data against a set of SHACL constraints to make sure that the conversion for each source is correctly defined
* run `java -jar target/cyber-kb-<version>-jar-with-dependencies.jar -p <type-of-source>` 
    * replace `<type-of-source>` with one of the following: capec, cwe, cve, cpe)
    * replace `<version>` with the version of the Cyber-KB
    * (optional) you can also add `-v` as parameter to activate SHACL constraint checking 
        * Note: this option may add a significant time to the process (especially for CPE)

The prototype will then 
* (i) generate the RDF graph from these sources and create necessary linking
* (ii) (*optional*) check the generated RDF data against a set of SHACL constraints (using constraints from `src/main/resources/shacl/*.ttl`)
* (iii) store the data in the triplestore

We have tried and tested it in OSX (Intel i7@3,1GHz, OSX Mojave, 16GB RAM). 
The benchmark result (excluding SHACL check) is available in the following [link](https://github.com/sepses/cyber-kg-converter/blob/master/doc/benchmark.png)

@SEPSES team
