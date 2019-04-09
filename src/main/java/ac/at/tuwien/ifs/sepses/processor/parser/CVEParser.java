package ac.at.tuwien.ifs.sepses.processor.parser;

import ac.at.tuwien.ifs.sepses.linking.CVELinking;
import ac.at.tuwien.ifs.sepses.processor.helper.Curl;
import ac.at.tuwien.ifs.sepses.processor.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.processor.updater.CVEUpdate;
import ac.at.tuwien.ifs.sepses.rml.XMLParser;
import ac.at.tuwien.ifs.sepses.vocab.CPE;
import ac.at.tuwien.ifs.sepses.vocab.CVE;
import ac.at.tuwien.ifs.sepses.vocab.CVSS;
import ac.at.tuwien.ifs.sepses.vocab.CWE;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.vocabulary.DCTerms;
import org.apache.jena.vocabulary.RDF;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.Properties;

public class CVEParser {

    private static final Logger log = LoggerFactory.getLogger(CVEParser.class);

    public static void main(String[] args) throws Exception {
        Properties prop = new Properties();
        FileInputStream ip = new FileInputStream("config.properties");
        prop.load(ip);
        parseCVE(prop);
    }

    public static void parseCVE(Properties prop) throws Exception {

        //============Configuration and URL================

        String urlCVE = prop.getProperty("CVEUrl");
        String urlCVEMeta = prop.getProperty("CVEMetaUrl");
        String destDir = prop.getProperty("InputDir") + "/cve";
        String outputDir = prop.getProperty("OutputDir") + "/cve";

        String RMLFileTemp = prop.getProperty("CVERMLTempFile");
        String RMLFile = prop.getProperty("CVERMLFile");
        String sparqlEndpoint = prop.getProperty("SparqlEndpoint");
        String namegraph = prop.getProperty("CVENamegraph");
        String CWEGraphName = prop.getProperty("CWENamegraph");
        String CPEGraphName = prop.getProperty("CPENamegraph");
        String active = prop.getProperty("CVEActive");

        Boolean isUseAuth = Boolean.parseBoolean(prop.getProperty("UseAuth"));
        String username = prop.getProperty("EndpointUser");
        String password = prop.getProperty("EndpointPass");

        //===========================================

        long start = System.currentTimeMillis() / 1000;
        long end;
        log.info("time_start: " + Instant.now());
        // Step 0a. Check if the system active
        if (!active.equals("Yes")) {
            log.info("Sorry, CVE Parser is inactive.. please activate it in the config file !");

        } else {
            // Step 0b. Checking CVE Meta...
            log.info("Checking resource meta from " + urlCVEMeta);
            String metafileName = urlCVEMeta.substring(urlCVEMeta.lastIndexOf("/") + 1);
            String metaDir = destDir + "/" + metafileName;
            String currentMeta = DownloadUnzip.downloadResource(urlCVEMeta, metaDir);
            Path currentMetaPath = Paths.get(currentMeta);
            String metaSHA = CVEUpdate.readMetaSHA(currentMetaPath.toString());
            boolean checkCVEMeta = CVEUpdate.checkSHAMeta(metaSHA, sparqlEndpoint, namegraph);

            if (checkCVEMeta) {
                // --> up to date
                log.info("  Resource is already up-to-date!");
                log.info("time_end: " + new Date());

            } else {
                // --> needs updating
                log.info("Resource is New!");
                org.apache.jena.rdf.model.Model CVEMetaModel = CVEUpdate.generateCVEMetaTriple(metaSHA);

                // Step 1. Downloading CVE resource from the internet...
                log.info("Downloading resource from internet...  ");
                String cvefileName = urlCVE.substring(urlCVE.lastIndexOf("/") + 1);
                String destCVEFile = destDir + "/" + cvefileName;
                String CVEZipFile = DownloadUnzip.downloadResource(urlCVE, destCVEFile);
                log.info("Downloading resource Done!");
                end = System.currentTimeMillis() / 1000;
                log.info(" in " + (end - start) + " seconds");
                start = end;

                // Step 2. Unziping resource...
                log.info("Unzipping resource to...  ");
                String UnzipFile = DownloadUnzip.unzip(CVEZipFile, destDir);
                log.info(UnzipFile + " Done!");
                end = System.currentTimeMillis() / 1000;
                log.info(" in " + (end - start) + " seconds");
                start = end;

                // Step 3. Injecting xml file...
                log.info("Injecting xml file...  ");
                String CVEXML = UnzipFile;
                String fileName = CVEXML.substring(CVEXML.lastIndexOf("/") + 1);
                if (fileName.indexOf("\\") >= 0) {
                    fileName = CVEXML.substring(CVEXML.lastIndexOf("\\") + 1);
                }
                Path path = Paths.get(CVEXML);
                Charset charset = StandardCharsets.UTF_8;
                String content = new String(Files.readAllBytes(path), charset);
                content = content.replaceAll("xmlns=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\"",
                        "xmlns:1=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\"");
                Files.write(path, content.getBytes(charset));
                log.info(" Done!");
                end = System.currentTimeMillis() / 1000;
                log.info(" in " + (end - start) + " seconds");
                start = end;

                // Checking updates
                log.info("Checking Updates... ");
                parseTempCVE(CVEXML, RMLFileTemp, sparqlEndpoint, namegraph);
                log.info("Done!");
                end = System.currentTimeMillis() / 1000;
                log.info(" in " + (end - start) + " seconds");
                start = end;

                // Step 4. Parsing xml to rdf......
                log.info("Parsing xml to rdf...  ");
                parseCVE(CVEXML, RMLFile, sparqlEndpoint, CWEGraphName, CPEGraphName, outputDir, CVEMetaModel);
                log.info("Done!");
                end = System.currentTimeMillis() / 1000;
                log.info(" in " + (end - start) + " seconds");
                start = end;

                // Step 5. Storing data to triple store....
                log.info("Storing data to triple store....  ");
                String output = outputDir + "/" + fileName + "-output.ttl";

                //                 Step 5a. delete previous CVEMeta
                CVEUpdate.deleteCVEMeta(sparqlEndpoint, namegraph);

                // Step 5b. store data
                Curl.storeData(output, namegraph, sparqlEndpoint, isUseAuth, username, password);
                log.info("Done!");
                end = System.currentTimeMillis() / 1000;
                log.info(" in " + (end - start) + " seconds");
                start = end;

                // Finished!
                log.info("time_end: " + new Date());
            }
        }
    }

    public static void parseTempCVE(String CVEXMLFile, String RMLFileTemp, String CyberKnowledgeEp,
            String CVEGraphName) throws Exception {

        //String xmlFileName = "./input/cvedecade/nvdcve-2.0-2018.xml";
        String fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("/") + 1);
        if (fileName.indexOf("\\") >= 0) {
            fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("\\") + 1);
        }
        //log.info(fileName);System.exit(0);
        org.apache.jena.rdf.model.Model CVEModelTemp = XMLParser.Parse(CVEXMLFile, RMLFileTemp);
        ArrayList<String>[] CVEArray = CVEUpdate.checkExistingCVE(CVEModelTemp, CyberKnowledgeEp, CVEGraphName);
        log.info("Done!");
        log.info("Found New CVE: " + CVEArray[0].size());
        log.info("Found modified CVE : " + CVEArray[1].size());
        log.info("Found existing CVE : " + CVEArray[2].size());
        if ((CVEArray[0].size() == 0) && (CVEArray[1].size() == 0)) {
            log.info("CVE is already updated");
        }
        CVEModelTemp.close();

    }

    public static void parseCVE(String CVEXMLFile, String RMLFile, String CyberKnowledgeEp, String CWEGraphName,
            String CPEGraphName, String outputDir, org.apache.jena.rdf.model.Model CVEMetaModel) throws Exception {

        String fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("/") + 1);
        if (fileName.indexOf("\\") >= 0) {
            fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("\\") + 1);
        }
        org.apache.jena.rdf.model.Model CVEModel = XMLParser.Parse(CVEXMLFile, RMLFile);
        String test = outputDir + "/" + fileName + "-output.ttl";

        CVEModel.setNsPrefix("cve-res", "http://w3id.org/sepses/resource/cve/");
        CVEModel.setNsPrefix("cvss-res", "http://w3id.org/sepses/resource/cvss/");
        CVEModel.setNsPrefix("cve", CVE.NS);
        CVEModel.setNsPrefix("cpe", CPE.NS);
        CVEModel.setNsPrefix("cvss", CVSS.NS);
        CVEModel.setNsPrefix("cwe", CWE.NS);
        CVEModel.setNsPrefix("dct", DCTerms.NS);
        RDFDataMgr.write(new FileOutputStream(test), CVEModel, Lang.TURTLE);

        log.info("Generate ac.at.tuwien.ifs.sepses.linking...");
        //System.exit(0);
        //CVEModel.write(System.out,"TURTLE");System.exit(0);
        org.apache.jena.rdf.model.Model CVETOCPE =
                CVELinking.generateLinkingCVETOCPE(CVEModel, CyberKnowledgeEp, CPEGraphName, fileName, outputDir);
        org.apache.jena.rdf.model.Model CVETOCWE =
                CVELinking.generateLinkingCVETOCWE(CVEModel, CyberKnowledgeEp, CWEGraphName, fileName, outputDir);
        //remove unnecessary triples (literal cpeId & cweId)
        Property cpeId = CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cve#cpeId");
        Property cweId = CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cve#cweId");
        Property hasVulnerableConfiguration =
                CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cve#hasVulnerableConfiguration");
        Property hasLogicalTest = CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTest");
        Property logicalTestFactRef =
                CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cpe#logicalTestFactRef");
        Property logicalTestOperator =
                CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cpe#logicalTestOperator");
        Property logicalTestNegate =
                CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cpe#logicalTestNegate");
        Resource LogicalTest = CVEModel.createResource("http://w3id.org/sepses/vocab/ref/cpe#LogicalTest");
        CVEModel.removeAll(null, cpeId, null);
        CVEModel.removeAll(null, hasLogicalTest, null);
        CVEModel.removeAll(null, logicalTestFactRef, null);
        CVEModel.removeAll(null, logicalTestOperator, null);
        CVEModel.removeAll(null, logicalTestNegate, null);
        CVEModel.removeAll(null, cweId, null);
        CVEModel.removeAll(null, hasVulnerableConfiguration, null);
        CVEModel.removeAll(null, RDF.type, LogicalTest);

        org.apache.jena.rdf.model.Model allCVE = CVEModel.union(CVETOCWE).union(CVETOCPE).union(CVEMetaModel);

        //get an output file out of the model
        String allCVEfileName = outputDir + "/" + fileName + "-output.ttl";
        //String cveModelfileName = "output/"+fileName+"-output-basic.ttl";
        FileWriter out = new FileWriter(allCVEfileName);
        // FileWriter out = new FileWriter(cveModelfileName);
        try {
            allCVE.write(out, "TURTLE");
            //CVEModel.write(out,"TURTLE");
        } finally {
            CVEModel.close();
            CVETOCPE.close();
            CVETOCWE.close();
        }
    }
}


    
   


