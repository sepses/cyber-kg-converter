package ac.at.tuwien.ifs.sepses.parser.impl;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.ResourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.topbraid.shacl.vocabulary.SH;

import ac.at.tuwien.ifs.sepses.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.helper.JSONParser;
import ac.at.tuwien.ifs.sepses.helper.Utility;
import ac.at.tuwien.ifs.sepses.helper.XMLParser;
import ac.at.tuwien.ifs.sepses.parser.Parser;
import ac.at.tuwien.ifs.sepses.parser.tool.CATTool;
import ac.at.tuwien.ifs.sepses.storage.Storage;
import ac.at.tuwien.ifs.sepses.vocab.CAPEC;
import ac.at.tuwien.ifs.sepses.vocab.CAT;

public class CATParser implements Parser {
	private static final Logger log = LoggerFactory.getLogger(CATParser.class);

    private final String urlCAT;
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

    public CATParser(Properties properties) {

        urlCAT = properties.getProperty("CATUrl");
        destDir = properties.getProperty("InputDir") + "/cat";
        outputDir = properties.getProperty("OutputDir") + "/cat";
        rmlMetaModel = properties.getProperty("CATRMLTempFile");
        rmlFile = properties.getProperty("CATRMLFile");
        namegraph = properties.getProperty("CATNamegraph");
        active = properties.getProperty("CATActive");

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

        Parser parser = new CATParser(prop);
        parser.parse(false);
    }

    @Override public void parse(Boolean isShaclActive) throws IOException {

        if (!active.equals("Yes")) {
            log.warn("Sorry, Attack Parser is inactive.. please activate it in the config file !");

        } else {
            Model model = getModelFromLastUpdate();
            if (isShaclActive) {
                Model checkResults = Utility.validateWithShacl("shacl/attack.ttl", model);
                if (checkResults.contains(null, SH.conforms, ResourceFactory.createTypedLiteral(false))) {
                    throw new IOException("Attack Validation Error: " + checkResults.toString());
                }
                checkResults.close();
                log.info("Attack Validation Succeeded");
            } else if (!model.isEmpty()) {
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

        // Step 1 - Downloading Attack resource from the internet...
        log.info("Downloading CAT file from " + urlCAT);
        String catFileName = urlCAT.substring(urlCAT.lastIndexOf("/") + 1);
        String destCATFile = destDir + "/" + catFileName;
        String CATFile = DownloadUnzip.downloadResource(urlCAT, destCATFile);
      // System.out.println(CATFile);
        log.info("CAT file downloaded");
        //String CATFile = "input/cat/enterprise-attack.json";
        model = parseCAT(CATFile, rmlFile);
        System.out.println("update CAT");
        CATTool.updateCATLinks(model);
    
    end = System.currentTimeMillis() / 1000;
    log.info("CAPEC parser finished in " + (end - start) + " seconds");

    return model;
    }

    @Override public String saveModelToFile(Model model) {
        return Utility.saveToFile(model, outputDir, urlCAT);
    }

    @Override public void storeFileInRepo(String filename) {

        log.info("Store data to " + sparqlEndpoint + " using graph " + namegraph);
        storage.replaceData(filename, sparqlEndpoint, namegraph, isUseAuth, user, pass);
    }

    private Model parseCAT(String CATFile, String RMLFile) throws IOException {
        log.info("Parsing json to rdf...  ");
        //System.out.print(CATFile);
        Model catModel = JSONParser.Parse(CATFile, RMLFile);
        //catModel.write(System.out,"TURTLE");
        //System.exit(0);
        //Linker.updateCapecLinks(catModel);
        Integer countCAT = Utility.countInstance(catModel, CAT.ATTACK_PATTERN);
        log.info("The number of CAT instances parsed: " + countCAT);
        log.info("Parsing done..!");
        //	System.exit(0);
        return catModel;
    }

}
