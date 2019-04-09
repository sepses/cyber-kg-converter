package ac.at.tuwien.ifs.sepses.processor.parser;

import ac.at.tuwien.ifs.sepses.processor.helper.Curl;
import ac.at.tuwien.ifs.sepses.processor.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.processor.updater.CPEUpdate;
import ac.at.tuwien.ifs.sepses.rml.XMLParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.Properties;

public class CPEParser {

    private static final Logger log = LoggerFactory.getLogger(CPEParser.class);

    public static void main(String[] args) throws Exception {
        Properties prop = new Properties();
        FileInputStream ip = new FileInputStream("config.properties");
        prop.load(ip);
        parseCPE(prop);
    }

    public static void parseCPE(Properties prop) throws Exception {

        //============Configuration and URL================

        String urlCPE = prop.getProperty("CPEUrl");
        String destDir = prop.getProperty("InputDir") + "/cpe";
        String outputDir = prop.getProperty("OutputDir") + "/cpe";

        String RMLFileTemp = prop.getProperty("CPERMLTempFile");
        String RMLFile = prop.getProperty("CPERMLFile");
        String sparqlEndpoint = prop.getProperty("SparqlEndpoint");
        String namegraph = prop.getProperty("CPENamegraph");
        String active = prop.getProperty("CPEActive");

        Boolean isUseAuth = Boolean.parseBoolean(prop.getProperty("UseAuth"));
        String username = prop.getProperty("EndpointUser");
        String password = prop.getProperty("EndpointPass");

        //===========================================
        //0. Check if the system active
        log.info("time_start: " + new Date());
        if (!active.equals("Yes")) {
            log.info("Sorry, CPE Parser is inactive.. please activate it in the config file !");

        } else {

            //1. Downloading CPE resource from the internet...
            log.info("Downloading resource from " + urlCPE);
            String cpefileName = urlCPE.substring(urlCPE.lastIndexOf("/") + 1);
            String destCPEFile = destDir + "/" + cpefileName;
            String CPEZipFile = DownloadUnzip.downloadResource(urlCPE, destCPEFile);
            log.info("   Done!");

            //2. Unziping resource...
            log.info("Unzipping resource to...  ");
            String UnzipFile = DownloadUnzip.unzip(CPEZipFile, destDir);
            //System.exit(0);
            log.info(UnzipFile + "  Done!");

            //3. Injecting xml file...
            log.info("Injecting xml file...  ");
            String CPEXML = UnzipFile;
            String fileName = CPEXML.substring(CPEXML.lastIndexOf("/") + 1);
            if (fileName.indexOf("\\") >= 0) {
                fileName = CPEXML.substring(CPEXML.lastIndexOf("\\") + 1);
            }
            Path path = Paths.get(CPEXML);
            Charset charset = StandardCharsets.UTF_8;

            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(CPEXML)));
                String co = null;
                StringBuffer inputBuffer = new StringBuffer();
                int c = 0;
                while ((co = reader.readLine()) != null) {
                    c++;
                    if (c == 2) {
                        co = co.replaceAll("xmlns=\"http://cpe.mitre.org/dictionary/2.0\"",
                                "xmlns:1=\"http://cpe.mitre.org/dictionary/2.0\"");
                    }
                    inputBuffer.append(co);
                    inputBuffer.append('\n');
                }
                String inputStr = inputBuffer.toString();
                FileWriter fw = new FileWriter(CPEXML);
                BufferedWriter bw = new BufferedWriter(fw);
                log.info("write xml file");
                bw.write(inputStr);
                try {
                    if (bw != null)
                        bw.close();
                } catch (Exception ex) {
                    log.info("Error in closing the BufferedWriter" + ex);
                }
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
            log.info("Done!");

            //4.0 Checking ac.at.tuwien.ifs.sepses.processor...
            log.info("Checking updates from " + sparqlEndpoint + " using graphname " + namegraph);
            String c = CPEUpdate.checkExistingTriple(sparqlEndpoint, namegraph);
            log.info("existing cpe = " + c);

            long start = System.currentTimeMillis() / 1000;
            long end;
            org.apache.jena.rdf.model.Model CPEModelTemp = XMLParser.Parse(CPEXML, RMLFileTemp);
            end = System.currentTimeMillis() / 1000;
            log.info(" in " + (end - start) + " seconds");
            start = end;

            boolean sameVersion = CPEUpdate.checkingCPEVersion(CPEModelTemp, sparqlEndpoint, namegraph);
            if (sameVersion) {
                log.info("CPE is up-to-date!!");
                log.info("time_end: " + new Date());
            } else {

                log.info("CPE is NEW!!");
                //4. Parsing xml to rdf......
                log.info("Parsing xml to rdf...  ");
                boolean emptyTripleStore =
                        parseCPE(CPEXML, RMLFile, sparqlEndpoint, namegraph, outputDir, c, CPEModelTemp);

                end = System.currentTimeMillis() / 1000;
                log.info(" in " + (end - start) + " seconds");

                //delete the generator
                CPEUpdate.deleteGenerator(sparqlEndpoint, namegraph);
                log.info("Done!");

                //5. Storing data to triple store....
                log.info("Storing data to triple store....  ");
                String output = outputDir + "/" + fileName + "-output.ttl";
                if (emptyTripleStore) {
                    log.info("insert initial data");
                    Curl.storeData(output, namegraph, sparqlEndpoint, isUseAuth, username, password);
                } else {
                    log.info("update data");
                    Curl.storeData(output, namegraph, sparqlEndpoint, isUseAuth, username, password);
                }
                log.info("Done!");
                //Finish
                log.info("time_end: " + new Date());
            }
        }
    }

    public static boolean parseCPE(String CPEXMLFile, String RMLFile, String CyberKnowledgeEp, String CPEGraphName,
            String outputDir, String c, org.apache.jena.rdf.model.Model cPEModelTemp) throws Exception {

        String fileName = CPEXMLFile.substring(CPEXMLFile.lastIndexOf("/") + 1);
        if (fileName.indexOf("\\") >= 0) {
            fileName = CPEXMLFile.substring(CPEXMLFile.lastIndexOf("\\") + 1);
        }

        org.apache.jena.rdf.model.Model CPEModel = XMLParser.Parse(CPEXMLFile, RMLFile);
        String cpe = CPEUpdate.countCPE(CPEModel);
        org.apache.jena.rdf.model.Model addCPEModel = CPEUpdate.generateAdditionalTriples(CPEModel);
        log.info("CPE parsed: " + cpe.toString());

        org.apache.jena.rdf.model.Model allCPE = CPEModel.union(addCPEModel);
        allCPE = allCPE.union(cPEModelTemp);

        cPEModelTemp.close();
        addCPEModel.close();
        CPEModel.close();

        log.info("Parsing done..!");

        if (c.equals("0")) {
            log.info("produce turtle output file");
            Curl.produceOutputFile(allCPE, outputDir, fileName);
            return true;
        } else {
            log.info("produce turtle output file");
            Curl.produceOutputFile(allCPE, outputDir, fileName);
            return false;
        }
    }
}
