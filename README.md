# The SEPSES Cyber-KB Engine

This engine is designed as a RDF generation mechanism from several CyberSecurity resources.
In our server, we add additional bash command to run it continuously, but we didn't provide the script here.

To run this prototype, the prerequisite is that you have a JDK 8+ and Maven installed in your computer.
Additionally, the config.properties is build for local Jena fuseki installation. Make sure that: 
* the `config.properties` is available (and adjust it if necessary; especially with regards to the triplestore/fuseki installation)
* you have an empty repo called 'sepses' in your fuseki installation

The following steps are required to run the engine: 
* run `mvn clean` to build the required jar files from the `lib` folder
* run `mvn install` to build the application
* run `java -jar target/cyber-kb-1.0.2-jar-with-dependencies.jar`

By default, the application will run conversion for for all registered resources (CAPEC, CWE, CPE, CVE+CVSS)

The prototype will then 
* (i) test the parser with SHACL constraints to make sure that the conversion for each source is correctly defined
* (ii) generate the RDF graph from these sources and create necessary linking
* (iii) store the data in the triplestore

@SEPSES team
