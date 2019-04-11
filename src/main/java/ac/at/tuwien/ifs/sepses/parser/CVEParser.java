package ac.at.tuwien.ifs.sepses.parser;

import ac.at.tuwien.ifs.sepses.helper.Curl;
import ac.at.tuwien.ifs.sepses.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.helper.QueryUtility;
import ac.at.tuwien.ifs.sepses.parser.tool.Linker;
import ac.at.tuwien.ifs.sepses.parser.tool.CVETool;
import ac.at.tuwien.ifs.sepses.rml.XMLParser;
import ac.at.tuwien.ifs.sepses.vocab.CVE;
import org.apache.jena.rdf.model.Model;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
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
        String tempRMLFile = prop.getProperty("CVERMLTempFile");

        String sparqlEndpoint = prop.getProperty("SparqlEndpoint");
        String namegraph = prop.getProperty("CVENamegraph");
        String active = prop.getProperty("CVEActive");
        Integer startYear = Integer.parseInt(prop.getProperty("CVEYearStart"));
        Integer endYear = Integer.parseInt(prop.getProperty("CVEYearEnd"));

        //===========================================
        // Step 0a. Check if the system active
        if (!active.equals("Yes")) {
            log.info("Sorry, CVE Parser is inactive.. please activate it in the config file !");

//        } else if (QueryUtility.checkIsGraphNotEmpty(sparqlEndpoint, namegraph, CVE.CVE)) {
//            // ** if CVE already initialized
//            internalCVEParser(prop, urlCVE, urlCVEMeta, 1);
//
        } else {
            // ** if initial import
            initialCVEParser(prop, startYear, endYear);
            // ** if CVE already initialized
            internalCVEParser(prop, urlCVE, urlCVEMeta, 1);
        }
    }

    public static void parseTempCVE(String CVEXMLFile, String RMLFileTemp, String CyberKnowledgeEp,
            String CVEGraphName) throws IOException {

        //String xmlFileName = "./input/cvedecade/nvdcve-2.0-2018.xml";
        String fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("/") + 1);
        if (fileName.indexOf("\\") >= 0) {
            fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("\\") + 1);
        }
        Model CVEModelTemp = XMLParser.Parse(CVEXMLFile, RMLFileTemp);
        ArrayList<String>[] CVEArray = CVETool.checkExistingCVE(CVEModelTemp, CyberKnowledgeEp, CVEGraphName);
        log.info("Done!");
        log.info("Found New CVE: " + CVEArray[0].size());
        log.info("Found modified CVE : " + CVEArray[1].size());
        log.info("Found existing CVE : " + CVEArray[2].size());
        if ((CVEArray[0].size() == 0) && (CVEArray[1].size() == 0)) {
            log.info("CVE is already updated");
        }
        CVEModelTemp.close();

    }

    public static String parseCVE(String CVEXMLFile, String RMLFile, String CyberKnowledgeEp, String CWEGraphName,
            String CPEGraphName, String outputDir, Model CVEMetaModel) throws IOException {

        String fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("/") + 1);
        if (fileName.indexOf("\\") >= 0) {
            fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("\\") + 1);
        }
        Model CVEModel = XMLParser.Parse(CVEXMLFile, RMLFile);
        Linker.updateCveLinks(CVEModel);
        log.info("adding CVE Metamodel");
        CVEModel.add(CVEMetaModel);

        //get an output file out of the model
        String path = outputDir + "/" + fileName + "-output.ttl";
        File resultFile = new File(path);
        resultFile.getParentFile().mkdirs();
        FileWriter out = new FileWriter(resultFile);
        try {
            CVEModel.write(out, "TURTLE");
        } finally {
            CVEModel.close();
            return path;
        }
    }

    private static void initialCVEParser(Properties prop, int startYear, int endYear) throws Exception {

        //============Configuration and URL================

        String urlCVE = prop.getProperty("CVEUrl");
        String urlCVEMeta = prop.getProperty("CVEMetaUrl");

        // iterate through the years
        for (int i = startYear; i <= endYear; i++) {
            // inject year
            String cveUrlYear = urlCVE.replace("modified", String.valueOf(i));
            String cveMetaUrlYear = urlCVEMeta.replace("modified", String.valueOf(i));

            internalCVEParser(prop, cveUrlYear, cveMetaUrlYear, i);
        }
    }

    private static void internalCVEParser(Properties prop, String cveUrlYear, String cveMetaUrlYear, Integer year)
            throws IOException {

        String destDir = prop.getProperty("InputDir") + "/cve";
        String outputDir = prop.getProperty("OutputDir") + "/cve";

        String RMLFile = prop.getProperty("CVERMLFile");
        String RMLTempFile = prop.getProperty("CVERMLTempFile");
        String sparqlEndpoint = prop.getProperty("SparqlEndpoint");
        String namegraph = prop.getProperty("CVENamegraph");
        String CWEGraphName = prop.getProperty("CWENamegraph");
        String CPEGraphName = prop.getProperty("CPENamegraph");

        Boolean isUseAuth = Boolean.parseBoolean(prop.getProperty("UseAuth"));
        String username = prop.getProperty("EndpointUser");
        String password = prop.getProperty("EndpointPass");

        long start = System.currentTimeMillis() / 1000;
        long end;
        log.info("time_start: " + Instant.now());

        // Step 0b. Checking CVE Meta...
        log.info("Checking resource meta from " + cveMetaUrlYear);
        String metaFileName = cveMetaUrlYear.substring(cveMetaUrlYear.lastIndexOf("/") + 1);
        String metaDir = destDir + "/" + metaFileName;
        String currentMeta = DownloadUnzip.downloadResource(cveMetaUrlYear, metaDir);
        Path currentMetaPath = Paths.get(currentMeta);
        String metaSHA = CVETool.readMetaSHA(currentMetaPath.toString());

        // --> needs update
        log.info("generate cve meta model");
        Model CVEMetaModel = CVETool.generateCVEMetaTriple(metaSHA, year);

        // Step 1. Downloading CVE resource from the internet...
        log.info("Downloading resource from internet...  ");
        String cvefileName = cveUrlYear.substring(cveUrlYear.lastIndexOf("/") + 1);
        String destCVEFile = destDir + "/" + cvefileName;
        String CVEZipFile = DownloadUnzip.downloadResource(cveUrlYear, destCVEFile);
        log.info("Downloading resource Done!");

        // Step 2. Unzipping resource...
        log.info("Unzipping resource to...  ");
        String UnzipFile = DownloadUnzip.unzip(CVEZipFile, destDir);
        log.info(UnzipFile + " Done!");

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

        // (optional - only for CVE-modified)
        if (year == 1) {
            parseTempCVE(CVEXML, RMLTempFile, sparqlEndpoint, namegraph);
        }

        // Step 4. Parsing xml to rdf......
        log.info("Parsing xml to rdf...  ");
        String output =
                parseCVE(CVEXML, RMLFile, sparqlEndpoint, CWEGraphName, CPEGraphName, outputDir, CVEMetaModel);
        log.info("Done!");

        // Step 5. Storing data to triple store....
        log.info("Storing data to triple store....  ");

        // Step 5a. delete previous CVEMeta
        CVETool.deleteCVEMeta(sparqlEndpoint, namegraph);

        // Step 5b. store data
        Curl.storeData(output, namegraph, sparqlEndpoint, isUseAuth, username, password);

        log.info("Done!");
        end = System.currentTimeMillis() / 1000;
        log.info("[Year-" + year + "] CVE Processing is done in " + (end - start) + " seconds");
    }
}


    
   


