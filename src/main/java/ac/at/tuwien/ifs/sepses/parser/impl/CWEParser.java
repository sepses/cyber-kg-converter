package ac.at.tuwien.ifs.sepses.parser.impl;

import ac.at.tuwien.ifs.sepses.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.helper.Utility;
import ac.at.tuwien.ifs.sepses.helper.XMLParser;
import ac.at.tuwien.ifs.sepses.parser.Parser;
import ac.at.tuwien.ifs.sepses.parser.tool.Linker;
import ac.at.tuwien.ifs.sepses.storage.Storage;
import ac.at.tuwien.ifs.sepses.vocab.CWE;
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
import java.util.Properties;

public class CWEParser implements Parser {

    private static final Logger log = LoggerFactory.getLogger(CWEParser.class);

    private final String urlCWE;
    private final String destDir;
    private final String outputDir;
    private final String rmlMetaModel;
    private final String rmlFile;
    private final String sparqlEndpoint;
    private final String namegraph;
    private final String active;
    private final Boolean isUseAuth;
    private final String user;
    private final String pass;

    private final Storage storage;

    public CWEParser(Properties properties) {

        urlCWE = properties.getProperty("CWEUrl");
        destDir = properties.getProperty("InputDir") + "/cwe";
        outputDir = properties.getProperty("OutputDir") + "/cwe";
        rmlMetaModel = properties.getProperty("CWERMLTempFile");
        rmlFile = properties.getProperty("CWERMLFile");
        namegraph = properties.getProperty("CWENamegraph");
        active = properties.getProperty("CWEActive");

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

        Parser parser = new CWEParser(prop);
        parser.parse(false);

    }

    @Override public void parse(Boolean isShaclActive) throws IOException {
        if (!active.equals("Yes")) {
            log.warn("Sorry, CWE Parser is inactive.. please activate it in the config file !");

        } else {
            Model model = getModelFromLastUpdate();
            if (model.isEmpty())
                return;

            if (isShaclActive) {
                Model checkResults = Utility.validateWithShacl("shacl/cwe.ttl", model);
                if (checkResults.contains(null, SH.conforms, ResourceFactory.createTypedLiteral(false))) {
                    throw new IOException("CWE Validation Error: " + checkResults.toString());
                }
                checkResults.close();
                log.info("CWE Validation Succeeded");
            } else {
                String filename = saveModelToFile(model);
                storeFileInRepo(filename);
            }
            model.close();
        }
    }

    @Override public Model getModelFromLastUpdate() throws IOException {
        Model model = null;

      

        //===========================================
        // Step 1 - Downloading CWE resource from the internet...
        log.info("Downloading resource from " + urlCWE);
        String cwefileName = urlCWE.substring(urlCWE.lastIndexOf("/") + 1);
        String destCWEFile = destDir + "/" + cwefileName;
        String CWEZipFile = DownloadUnzip.downloadResource(urlCWE, destCWEFile);
        log.info("  Done!");

        // Step 2 - Unziping resource...
        log.info("Unzipping resource to...  ");
        String UnzipFile = DownloadUnzip.unzip(CWEZipFile, destDir);
        log.info(UnzipFile + "  Done!");

        // Step 3 - Renaming and adapt xml file...
        log.info("Renaming and adapt XML file...  ");
        String CWEXML = UnzipFile;
        String fileName = CWEXML.substring(CWEXML.lastIndexOf("/") + 1);
        if (fileName.indexOf("\\") >= 0) {
            fileName = CWEXML.substring(CWEXML.lastIndexOf("\\") + 1);
        }
        Path path = Paths.get(CWEXML);
        String content = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        content =
                content.replaceAll("xmlns=\"http://cwe.mitre.org/cwe-7\"", "xmlns:c=\"http://cwe.mitre.org/cwe-7\"");
        Files.write(path, content.getBytes(StandardCharsets.UTF_8));
        log.info("... done!");

        // Step 4 - Checking whether the current CWE content is up-to-date...
        log.info("Checking updates from " + sparqlEndpoint + " using graphname " + namegraph);
        boolean cat = Utility.checkIsUpToDate(XMLParser.Parse(CWEXML, rmlMetaModel), sparqlEndpoint, namegraph,
                CWE.WEAKNESS_CATALOG);
         //boolean cat=false
        // timer
        long start = System.currentTimeMillis() / 1000;
        long end;
        if (cat) {
            log.info("CWE is up-to-date...! ");
            model = ModelFactory.createDefaultModel();

        } else {
            // Step 5 - Parsing xml to rdf......
            log.info("The downloaded CWE data is new...! ");
            model = parseCWE(CWEXML, rmlFile);
        }

        end = System.currentTimeMillis() / 1000;
        log.info("CWE processing finished in " + (end - start) + " seconds");

        return model;
    }

    @Override public String saveModelToFile(Model model) {
        return Utility.saveToFile(model, outputDir, urlCWE);
    }

    @Override public void storeFileInRepo(String filename) {
        log.info("Store data to " + sparqlEndpoint + " using graph " + namegraph);
        storage.replaceData(filename, sparqlEndpoint, namegraph, isUseAuth, user, pass);
    }

    private Model parseCWE(String cweXmlFile, String rmlFile) throws IOException {
        log.info("Parsing xml to rdf...  ");

        Model cweModel = XMLParser.Parse(cweXmlFile, rmlFile);
        Linker.updateCweLinks(cweModel);

        Integer cweCount = Utility.countInstance(cweModel, CWE.CWE);
        log.info("The number of CWE instances parsed: " + cweCount);
        log.info("Parsing done..!");

        return cweModel;
    }
}
    

    
 
        

    


    
   


