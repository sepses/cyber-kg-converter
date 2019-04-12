package ac.at.tuwien.ifs.sepses.storage.impl;

import ac.at.tuwien.ifs.sepses.storage.Storage;
import org.apache.commons.io.IOUtils;
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
import java.io.InputStream;

public enum FusekiStorage implements Storage {

    INSTANCE();

    private static final Logger log = LoggerFactory.getLogger(FusekiStorage.class);

    public static FusekiStorage getInstance() {
        return INSTANCE;
    }

    @Override
    public void storeData(String filename, String endpoint, String namegraph, Boolean isUseAuth, String user,
            String pass) {
        if (isUseAuth) {
            log.error("not handled yet");
        }

        long start = System.currentTimeMillis() / 1000;

        try {
            log.info("storing " + filename + " started");
            String command = "s-post " + endpoint + " " + namegraph + " " + filename;
            Process process = Runtime.getRuntime().exec(command);
            InputStream is = process.getInputStream();
            IOUtils.copy(is, System.out);
            log.info("Data appended successfully");
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }

        long end = System.currentTimeMillis() / 1000;
        log.info("Writing process for '" + filename + "' took " + (end - start) + " seconds");
    }

    @Override public void replaceData(String file, String endpoint, String namegraph, Boolean isUseAuth, String user,
            String pass) {

        long start = System.currentTimeMillis() / 1000;

        if (isUseAuth) {
            log.error("Auth is not handled yet");
            return;
        }

        try {
            log.info("storing " + file + " started");
            String command = "s-put " + endpoint + " " + namegraph + " " + file;
            Process process = Runtime.getRuntime().exec(command);
            InputStream is = process.getInputStream();
            IOUtils.copy(is, System.out);
            log.info("Data replaced successfully");
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }

        long end = System.currentTimeMillis() / 1000;
        log.info("Writing process for '" + file + "' took " + (end - start) + " seconds");

    }

    @Override public void deleteData(String endpoint, String namegraph, Boolean isUseAuth, String user, String pass) {

        if (isUseAuth) {
            log.error("Auth in Fuseki is not handled yet");
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
