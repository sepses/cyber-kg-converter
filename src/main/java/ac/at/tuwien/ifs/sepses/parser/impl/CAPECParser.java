package ac.at.tuwien.ifs.sepses.parser.impl;

import ac.at.tuwien.ifs.sepses.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.helper.Utility;
import ac.at.tuwien.ifs.sepses.helper.XMLParser;
import ac.at.tuwien.ifs.sepses.parser.Parser;
import ac.at.tuwien.ifs.sepses.parser.tool.Linker;
import ac.at.tuwien.ifs.sepses.storage.Storage;
import ac.at.tuwien.ifs.sepses.vocab.CAPEC;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

public class CAPECParser implements Parser {

    private static final Logger log = LoggerFactory.getLogger(CAPECParser.class);

    private final String urlCAPEC;
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

    public CAPECParser(Properties properties) {

        urlCAPEC = properties.getProperty("CAPECUrl");
        destDir = properties.getProperty("InputDir") + "/capec";
        outputDir = properties.getProperty("OutputDir") + "/capec";
        rmlMetaModel = properties.getProperty("CAPECRMLTempFile");
        rmlFile = properties.getProperty("CAPECRMLFile");
        namegraph = properties.getProperty("CAPECNamegraph");
        active = properties.getProperty("CAPECActive");

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

        Parser parser = new CAPECParser(prop);
        parser.parse();
    }

    @Override public void parse() throws IOException {

        if (!active.equals("Yes")) {
            log.warn("Sorry, CAPEC Parser is inactive.. please activate it in the config file !");

        } else {
            Model model = getModelFromLastUpdate();
            if (!model.isEmpty()) {
                String filename = saveModelToFile(model);
                storeFileInRepo(filename);
            }
            model.close();
        }
    }

    @Override public Model getModelFromLastUpdate() throws IOException {
        long start = System.currentTimeMillis() / 1000;
        long end;

        Model model = null;

        // Step 1 - Downloading CAPEC resource from the internet...
        log.info("Downloading CAPEX file from " + urlCAPEC);
        String capecFileName = urlCAPEC.substring(urlCAPEC.lastIndexOf("/") + 1);
        String destCAPECFile = destDir + "/" + capecFileName;
        String CAPECZipFile = DownloadUnzip.downloadResource(urlCAPEC, destCAPECFile);
        log.info("CAPEX file downloaded");

        // Step 2 - Unziping resource...
        log.info("Unzipping CAPEX file into ");
        String UnzipFile = DownloadUnzip.unzip(CAPECZipFile, destDir);
        log.info(UnzipFile + " - Done!");

        // Step 3 - Injecting xml file...
        String capecXML = UnzipFile;
        String fileName = capecXML.substring(capecXML.lastIndexOf("/") + 1);
        if (fileName.indexOf("\\") >= 0) {
            fileName = capecXML.substring(capecXML.lastIndexOf("\\") + 1);
        }
        log.info("adjusting filename: " + fileName);
        Path path = Paths.get(capecXML);
        String content = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        content = content.replaceAll("xmlns=\"http://capec.mitre.org/capec-3\"",
                "xmlns:1=\"http://capec.mitre.org/capec-3\"");
        Files.write(path, content.getBytes(StandardCharsets.UTF_8));

        // Step 4 - Checking whether CAPEC is up-to-date ...
        log.info("Checking updates from " + sparqlEndpoint + " using graphname " + namegraph);
        Boolean cat = Utility.checkIsUpToDate(XMLParser.Parse(capecXML, rmlMetaModel), sparqlEndpoint, namegraph,
                CAPEC.ATTACK_PATTERN_CATALOG);
        if (cat) {
            log.info("CAPEC is up-to-date...! ");
            model = ModelFactory.createDefaultModel();

        } else {
            log.info("CAPEC is new...! ");

            //4. Parsing xml to rdf......
            model = parseCAPEC(capecXML, rmlFile);
        }
        end = System.currentTimeMillis() / 1000;
        log.info("CAPEC parser finished in " + (end - start) + " seconds");

        return model;
    }

    @Override public String saveModelToFile(Model model) {
        return Utility.saveToFile(model, outputDir, urlCAPEC);
    }

    @Override public void storeFileInRepo(String filename) {

        log.info("Store data to " + sparqlEndpoint + " using graph " + namegraph);
        storage.replaceData(filename, sparqlEndpoint, namegraph, isUseAuth, user, pass);
    }

    private Model parseCAPEC(String capecXmlFile, String RMLFile) throws IOException {
        log.info("Parsing xml to rdf...  ");
        Model capecModel = XMLParser.Parse(capecXmlFile, RMLFile);
        Linker.updateCapecLinks(capecModel);
        Integer countCAPEC = Utility.countInstance(capecModel, CAPEC.CAPEC);
        log.info("The number of CAPEC instances parsed: " + countCAPEC);
        log.info("Parsing done..!");

        return capecModel;
    }
}
    

    
 
        

    


    
   


