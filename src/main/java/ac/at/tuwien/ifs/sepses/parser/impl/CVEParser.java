package ac.at.tuwien.ifs.sepses.parser.impl;

import ac.at.tuwien.ifs.sepses.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.helper.Utility;
import ac.at.tuwien.ifs.sepses.helper.XMLParser;
import ac.at.tuwien.ifs.sepses.parser.Parser;
import ac.at.tuwien.ifs.sepses.parser.tool.CVETool;
import ac.at.tuwien.ifs.sepses.parser.tool.Linker;
import ac.at.tuwien.ifs.sepses.storage.Storage;
import ac.at.tuwien.ifs.sepses.vocab.CVE;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.ResourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.topbraid.shacl.vocabulary.SH;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Properties;

public class CVEParser implements Parser {

    private static final Logger log = LoggerFactory.getLogger(CVEParser.class);

    private final String urlCVE;
    private final String urlCVEMeta;
    private final String destDir;
    private final String outputDir;
    private final String rmlMetaModel;
    private final String rmlFile;
    private final String sparqlEndpoint;
    private final String namegraph;
    private final String active;
    private final Integer startYear;
    private final Integer endYear;
    private final Boolean isUseAuth;
    private final String user;
    private final String pass;
    private final Storage storage;

    private String cveUrlYear;
    private String cveMetaUrlYear;

    public CVEParser(Properties properties) {

        urlCVE = properties.getProperty("CVEUrl");
        urlCVEMeta = properties.getProperty("CVEMetaUrl");
        destDir = properties.getProperty("InputDir") + "/cve";
        outputDir = properties.getProperty("OutputDir") + "/cve";
        rmlMetaModel = properties.getProperty("CVERMLTempFile");
        rmlFile = properties.getProperty("CVERMLFile");
        namegraph = properties.getProperty("CVENamegraph");
        startYear = Integer.parseInt(properties.getProperty("CVEYearStart"));
        endYear = Integer.parseInt(properties.getProperty("CVEYearEnd"));
        active = properties.getProperty("CVEActive");

        sparqlEndpoint = properties.getProperty("SparqlEndpoint");
        isUseAuth = Boolean.parseBoolean(properties.getProperty("UseAuth"));
        user = properties.getProperty("EndpointUser");
        pass = properties.getProperty("EndpointPass");

        storage = Utility.getStorage(properties);
    }

    public static void main(String[] args) throws Exception {
        Properties prop = new Properties();
        FileInputStream ip = new FileInputStream("config.properties");
        prop.load(ip);
        ip.close();

        Parser parser = new CVEParser(prop);
        parser.parse(false);
    }

    @Override public void parse(Boolean isShaclActive) throws IOException {
        if (!active.equals("Yes")) {
            log.info("Sorry, CVE Parser is inactive.. please activate it in the config file !");

        } else {
            // ** if CVE not yet initialized
            if (!Utility.checkIsGraphNotEmpty(sparqlEndpoint, namegraph, CVE.CVE)) {
              
        	// ** iterate through the years
                for (int i = startYear; i <= endYear; i++) {
                    // inject year
                    cveUrlYear = urlCVE.replace("modified", String.valueOf(i));
                    cveMetaUrlYear = urlCVEMeta.replace("modified", String.valueOf(i));

                    internalExecution(i, isShaclActive);
                }
            }
            // ** execute last update
            cveUrlYear = urlCVE;
            cveMetaUrlYear = urlCVEMeta;
            internalExecution(1, isShaclActive);
        }
    }

    @Override public Model getModelFromLastUpdate() throws IOException {
        // not used
        cveUrlYear = urlCVE;
        cveMetaUrlYear = urlCVEMeta;
        return internalCVEParser(1, true);
    }

    @Override public String saveModelToFile(Model model) {
        return Utility.saveToFile(model, outputDir, cveUrlYear);
    }

    @Override public void storeFileInRepo(String filename) {

        log.info("delete previous CVE metadata in the triple store");
        CVETool.deleteCVEMeta(storage, sparqlEndpoint, namegraph, isUseAuth, user, pass);

        log.info("Store data to " + sparqlEndpoint + " using graph " + namegraph);
        storage.storeData(filename, sparqlEndpoint, namegraph, isUseAuth, user, pass);
    }

    private void internalExecution(Integer year, Boolean isShaclActive) throws IOException {
        Model model = internalCVEParser(year, isShaclActive);
        String file = saveModelToFile(model);
        storeFileInRepo(file);
    }

    public Boolean parseTempCVE(String CVEXMLFile, String RMLFileTemp, String CyberKnowledgeEp, String CVEGraphName)
            throws IOException {
        boolean isUpdated = false;

        //String xmlFileName = "./input/cvedecade/nvdcve-2.0-2018.xml";
        String fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("/") + 1);
        if (fileName.indexOf("\\") >= 0) {
            fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("\\") + 1);
        }
        Model CVEModelTemp = XMLParser.Parse(CVEXMLFile, RMLFileTemp);
        ArrayList<String>[] CVEArray =
                CVETool.checkExistingCVE(storage, CVEModelTemp, CyberKnowledgeEp, CVEGraphName, isUseAuth, user,
                        pass);
        log.info("Done!");
        log.info("Found New CVE: " + CVEArray[0].size());
        log.info("Found modified CVE : " + CVEArray[1].size());
        log.info("Found existing CVE : " + CVEArray[2].size());
        if ((CVEArray[0].size() == 0) && (CVEArray[1].size() == 0)) {
            isUpdated = true;
            log.info("CVE is already updated");
        }
        CVEModelTemp.close();
        return isUpdated;
    }

    private Model parseCVE(String CVEXMLFile, String RMLFile, Model CVEMetaModel, Boolean isShaclActive)
            throws IOException {
        Model model = XMLParser.Parse(CVEXMLFile, RMLFile);
        Linker.updateCveLinks(model);
        log.info("adding CVE Metamodel");
        model.add(CVEMetaModel);

        if (isShaclActive) {
            Model checkResults = Utility.validateWithShacl("shacl/cve.ttl", model);
            if (checkResults.contains(null, SH.conforms, ResourceFactory.createTypedLiteral(false))) {
                throw new IOException("CVE Validation Error: " + checkResults.toString());
            }
            checkResults.close();
            log.info("CVE Validation Succeeded");
        }
        return model;
    }

    private Model internalCVEParser(Integer year, Boolean isShaclActive) throws IOException {

        long start = System.currentTimeMillis() / 1000;
        long end;

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
        String content = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        content = content.replaceAll("xmlns=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\"",
                "xmlns:1=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\"");
        Files.write(path, content.getBytes(StandardCharsets.UTF_8));
        log.info(" Done!");

        // (optional - only for CVE-modified)
        if (year == 1) {
            if (parseTempCVE(CVEXML, rmlMetaModel, sparqlEndpoint, namegraph))
                return ModelFactory.createDefaultModel();
        }

        // Step 4. Parsing xml to rdf......
        log.info("Parsing xml to rdf...  ");
        Model model = parseCVE(CVEXML, rmlFile, CVEMetaModel, isShaclActive);

        log.info("Done!");
        end = System.currentTimeMillis() / 1000;
        log.info("[Year-" + year + "] CVE Processing is done in " + (end - start) + " seconds");

        return model;
    }
}


    
   


