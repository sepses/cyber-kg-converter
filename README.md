# The SEPSES-CSKG Engine (v2.1.0)

SEPSES-CSKG is a cybersecurity knowledge graph that integrates and links critical information such as vulnerabilities, weaknesses and attack patterns from various publicly available sources. The Knowledge Graph is continuously updated to reflect changes in various data sources used as inputs, i.e., CAPEC, CPE, CVE, CVSS, and CWE. This engine is designed as a RDF generation mechanism from several CyberSecurity resources. In our server, we add additional bash command to run it continuously, but we didn't provide the script here.

**New!** in Version 2.1.0, several additional resources for <u>Industrial Control System Cybersecurity (ICS-Sec)</u> are included, i.e., MITRE ATT&CK (Enterprise and ICS) and ICSA (Industrial Control System Advisory).

## Vocabularies
Several vocabularies are developed to represent the SEPSES-CSKG knowledge graphs, as follows:

| Ontology   | Prefix | Link                                                                                       |
|------------|--------|--------------------------------------------------------------------------------------------|
| ATT&CK     | attack | <a href="http://w3id.org/sepses/vocab/ref/attack" target="_blank">http://w3id.org/sepses/vocab/ref/attack</a> |
| ICSAdvisory| icsa   | <a href="http://w3id.org/sepses/vocab/ref/icsa" target="_blank">http://w3id.org/sepses/vocab/ref/icsa</a>     |
| CVE        | cve    | <a href="http://w3id.org/sepses/vocab/ref/cve" target="_blank">http://w3id.org/sepses/vocab/ref/cve</a>         |
| CPE        | cpe    | <a href="http://w3id.org/sepses/vocab/ref/cpe" target="_blank">http://w3id.org/sepses/vocab/ref/cpe</a>         |
| CVSS       | cvss   | <a href="http://w3id.org/sepses/vocab/ref/cvss" target="_blank">http://w3id.org/sepses/vocab/ref/cvss</a>       |
| CWE        | cwe    | <a href="http://w3id.org/sepses/vocab/ref/cwe" target="_blank">http://w3id.org/sepses/vocab/ref/cwe</a>         |
| CAPEC      | capec  | <a href="http://w3id.org/sepses/vocab/ref/capec" target="_blank">http://w3id.org/sepses/vocab/ref/capec</a>     |



## Installation

### Requirements

To run this prototype, the prerequisite is that you have a JDK 8+ and Maven installed in your computer.

### Configuration
Additionally, the config.properties is build for local Jena fuseki installation. Make sure that: 
* the `config.properties` is available (and adjust it if necessary; especially with regards to the triplestore/fuseki installation)
* you have an empty repo called 'sepses' in your fuseki/virtuoso installation
    * you can also run it without storing the data to triplestore using "dummy" as storage
    * currently still need an active sparql endpoint (TODO: to fix this).


### Run the Code

The following steps are required to run the engine: 
* run `mvn clean` to build the required jar files from the `lib` folder
* run `mvn install -DskipTests=true` to build the application
    * optionally, you can also run the tests (without the `-DskipTests=true`) to run checks of extracted data against a set of SHACL constraints to make sure that the conversion for each source is correctly defined
* run `java -jar target/cyber-kb-<version>-jar-with-dependencies.jar -p <type-of-source>` 
    * replace `<type-of-source>` with one of the following: capec, cwe, cve, cat, icsa )
    * replace `<version>` with the version of the Cyber-KB
    * (optional) you can also add `-v` as parameter to activate SHACL constraint checking 
        * Note: this option may add a significant time to the process (especially for CPE)

The prototype will then 
* (i) generate the RDF graph from these sources and create necessary linking
* (ii) (*optional*) check the generated RDF data against a set of SHACL constraints (using constraints from `src/main/resources/shacl/*.ttl`)
* (iii) store the data in the triplestore

We have tried and tested it in OSX (Intel i7@3,1GHz, OSX Mojave, 16GB RAM). 
The benchmark result (excluding SHACL check) is available in the following [link](https://github.com/sepses/cyber-kg-converter/blob/master/doc/benchmark.png)

## Access Services

Example queries are now added (`example-queries.txt`), which can be tested in our [SPARQL endpoint](https://w3id.org/sepses/sparql).

Other interface beyond SPARQL are also provided, such as [Linked Data Interface](https://sepses.ifs.tuwien.ac.at/index.php/cyber-kg/), [Triple Pattern Fragment](http://ldf-server.sepses.ifs.tuwien.ac.at/) and [Dump-files](https://sepses.ifs.tuwien.ac.at/index.php/datasets/)   (in .turtle and .HDT).


@SEPSES team
