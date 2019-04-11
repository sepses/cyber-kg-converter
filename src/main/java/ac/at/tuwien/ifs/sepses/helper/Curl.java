package ac.at.tuwien.ifs.sepses.helper;

import org.apache.commons.io.IOUtils;
import org.apache.jena.update.UpdateExecutionFactory;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateProcessor;
import org.apache.jena.update.UpdateRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;

public class Curl {

    // cheatsheet: https://jena.apache.org/documentation/fuseki2/soh.html

    private static final Logger log = LoggerFactory.getLogger(Curl.class);

    public static void main(String[] args) throws IOException {
        String file = "output/cve/update/linking/CVETOCPE_nvdcve-2.0-modified.xml201904031046_NoLinking.log.ttl";
        String base_url = "http://localhost:7200";
        String repo_id = "sepses";
        String command = "curl " + base_url + "/rest/data/import/url";
        log.info(command);
        Runtime.getRuntime().exec(command);
    }

    public static void storeData(String file, String namegraph) {
        try {
            log.info(file);
            String url = "http://localhost:8890/sparql-graph-crud-auth?graph-uri=" + namegraph;
            String user = "dba";
            String pass = "dba";
            String command = "curl --digest -u " + user + ":" + pass + " -v -X POST -T " + file + " " + url;
            Runtime.getRuntime().exec(command);
            log.info("Data stored successfully");
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }

    }

    public static void storeData(String file, String namegraph, String endpoint, boolean isUseAuth, String username,
            String password) {
        try {
            log.info(file);
            String command = "";
            if (isUseAuth) {
                log.error("not handled yet");
            } else {
                command = "s-post " + endpoint + " " + namegraph + " " + file;
            }
            Process process = Runtime.getRuntime().exec(command);
            InputStream is = process.getInputStream();
            IOUtils.copy(is, System.out);
            log.info("Data stored successfully");
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
    }

    public static void storeInitData(String file, String namegraph) {
        try {
            log.info(file);
            String url = "http://localhost:8890/sparql-graph-crud-auth?graph-uri=" + namegraph;
            String user = "dba";
            String pass = "dba";
            String command = "curl --digest -u " + user + ":" + pass + " -v -X PUT -T " + file + " " + url;
            Runtime.getRuntime().exec(command);
            log.info("Data stored successfully");
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
    }

    public static String produceOutputFile(org.apache.jena.rdf.model.Model model, String outputDir, String fileName) {
        String CPEfileName = outputDir + "/" + fileName + "-output.ttl";
        File outputFile = new File(CPEfileName);
        outputFile.getParentFile().mkdirs();
        try {
            FileWriter out = new FileWriter(outputFile);
            model.write(out, "TURTLE");
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
        return CPEfileName;
    }

    public static void dropGraph(String namegraph, String endpoint) {

        String queryString = "DROP GRAPH <" + namegraph + ">";
        String sparqlService = endpoint + "/update"; // Fuseki specific ..

        UpdateRequest request = UpdateFactory.create(queryString);
        UpdateProcessor queryExecution = UpdateExecutionFactory.createRemote(request, sparqlService);
        queryExecution.execute();
    }

}
