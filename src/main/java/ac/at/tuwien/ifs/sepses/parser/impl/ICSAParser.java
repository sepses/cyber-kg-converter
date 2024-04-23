package ac.at.tuwien.ifs.sepses.parser.impl;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ResourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.topbraid.shacl.vocabulary.SH;
import ac.at.tuwien.ifs.sepses.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.helper.Utility;
import ac.at.tuwien.ifs.sepses.helper.CSVParser;
import ac.at.tuwien.ifs.sepses.parser.Parser;
import ac.at.tuwien.ifs.sepses.parser.tool.ICSATool;
import ac.at.tuwien.ifs.sepses.storage.Storage;
import ac.at.tuwien.ifs.sepses.vocab.ICSA;

public class ICSAParser implements Parser {
	private static final Logger log = LoggerFactory.getLogger(ICSAParser.class);

    private final String urlICSA;
    private final String destDir;
    private final String outputDir;
    private final String rmlFile;
    private final String sparqlEndpoint;
    private final String namegraph;
    private final String active;
    private final Boolean isUseAuth;
    private final String user;
    private final String pass;

    private final Storage storage;

    public ICSAParser(Properties properties) {

        urlICSA = properties.getProperty("ICSAUrl");
        destDir = properties.getProperty("InputDir") + "/icsa";
        outputDir = properties.getProperty("OutputDir") + "/icsa";
        rmlFile = properties.getProperty("ICSARMLFile");
        namegraph = properties.getProperty("ICSANamegraph");
        active = properties.getProperty("ICSAActive");

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

        Parser parser = new ICSAParser(prop);
        parser.parse(false);
    }

    @Override public void parse(Boolean isShaclActive) throws IOException {

        if (!active.equals("Yes")) {
            log.warn("Sorry, ICSA Parser is inactive.. please activate it in the config file !");

        } else {
            Model model = getModelFromLastUpdate();
            if (isShaclActive) {
                Model checkResults = Utility.validateWithShacl("shacl/icsa.ttl", model);
                if (checkResults.contains(null, SH.conforms, ResourceFactory.createTypedLiteral(false))) {
                    throw new IOException("ICSA Validation Error: " + checkResults.toString());
                }
                checkResults.close();
                log.info("ICSA Validation Succeeded");
            } else if (!model.isEmpty()) {
                String filename = saveModelToFile(model);
                storeFileInRepo(filename);
            }
            model.close();
        }
    }

    @Override public Model getModelFromLastUpdate() throws IOException {
//        long start = System.currentTimeMillis() / 1000;
//        long end;

        Model model = null;

        // Step 1 - Downloading Attack resource from the internet...
        log.info("Downloading ICSA file from " + urlICSA);
        String icsaFileName = urlICSA.substring(urlICSA.lastIndexOf("/") + 1);
        String destICSAFile = destDir + "/" + icsaFileName;
        String ICSAFile = DownloadUnzip.downloadResource(urlICSA, destICSAFile);
      // System.out.println(ICSAFile);
        log.info("ICSA file downloaded");
        long start = System.currentTimeMillis() / 1000;
        long end;

        model = parseICSA(ICSAFile, rmlFile);
        System.out.println("update ICSA");
        ICSATool.createCVEConnection(model);
        ICSATool.createCWEConnection(model);
        ICSATool.createVendorConnection(model);
        ICSATool.createCriticalInfrastructureConnection(model);
        ICSATool.createCompanyHeadquearterConnection(model);
        ICSATool.createProductConnection(model);
        ICSATool.createProductDistributionConnection(model);
        
    
    end = System.currentTimeMillis() / 1000;
    log.info("ICSA parser finished in " + (end - start) + " seconds");

    return model;
    }

    @Override public String saveModelToFile(Model model) {
        return Utility.saveToFile(model, outputDir, urlICSA);
    }

    @Override public void storeFileInRepo(String filename) {

        log.info("Store data to " + sparqlEndpoint + " using graph " + namegraph);
        storage.replaceData(filename, sparqlEndpoint, namegraph, isUseAuth, user, pass);
    }

    private Model parseICSA(String ICSAFile, String RMLFile) throws IOException {
        log.info("Parsing csv to rdf...  ");
       	    
        Model icsaModel = CSVParser.Parse(ICSAFile, RMLFile);
        Integer countICSA = Utility.countInstance(icsaModel, ICSA.ICSA);
        log.info("The number of ICSA instances parsed: " + countICSA);
        log.info("Parsing done..!");
        return icsaModel;
    }

}
