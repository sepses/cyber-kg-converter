package ac.at.tuwien.ifs.sepses.storage.impl;

import ac.at.tuwien.ifs.sepses.storage.Storage;
import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.ResourceFactory;
import org.apache.jena.update.UpdateExecutionFactory;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateProcessor;
import org.apache.jena.update.UpdateRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class VirtuosoStorage implements Storage {

    private static final Logger log = LoggerFactory.getLogger(VirtuosoStorage.class);

    @Override public void storeData(String file, String endpoint, String namegraph, Boolean isUseAuth, String user,
            String pass) {
        try {
            log.info(file);
            // e.g., endpoint = 'http://localhost:8890/'
            String url = endpoint + "sparql-graph-crud-auth?graph-uri=" + namegraph;
            String command = "curl --digest -u " + user + ":" + pass + " -v -X PUT -T " + file + " " + url;
            Runtime.getRuntime().exec(command);
            log.info("Data stored successfully");
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }

    }

    @Override public void replaceData(String file, String endpoint, String namegraph, Boolean isUseAuth, String user,
            String pass) {
        try {
            log.info(file);
            // e.g., endpoint = 'http://localhost:8890/'
            String url = endpoint + "sparql-graph-crud-auth?graph-uri=" + namegraph;
            String command = "curl --digest -u " + user + ":" + pass + " -v -X POST -T " + file + " " + url;
            Runtime.getRuntime().exec(command);
            log.info("Data stored successfully");
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }

    }

    @Override public void deleteData(String endpoint, String namegraph, Boolean isUseAuth, String user, String pass) {

        if (isUseAuth) {
            log.error("Auth is not handled yet");
            return;
        }
        ParameterizedSparqlString query = new ParameterizedSparqlString("DROP GRAPH ?graph");
        Resource graphResource = ResourceFactory.createResource(namegraph);
        query.setParam("graph", graphResource);
        UpdateRequest updateRequest = UpdateFactory.create(query.toString());
        UpdateProcessor processor = UpdateExecutionFactory.createRemote(updateRequest, endpoint);

        processor.execute();

    }
}
