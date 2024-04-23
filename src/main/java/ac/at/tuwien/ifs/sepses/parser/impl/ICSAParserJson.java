package ac.at.tuwien.ifs.sepses.parser.impl;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.ResourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.topbraid.shacl.vocabulary.SH;
import ac.at.tuwien.ifs.sepses.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.helper.Utility;
import ac.at.tuwien.ifs.sepses.helper.JSONParser;
import ac.at.tuwien.ifs.sepses.parser.Parser;
import ac.at.tuwien.ifs.sepses.storage.Storage;
import ac.at.tuwien.ifs.sepses.vocab.ICSA;

public class ICSAParserJson implements Parser {
	private static final Logger log = LoggerFactory.getLogger(ICSAParserJson.class);

    private final String urlICSA;
    private final String urlIndexICSA;
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

    public ICSAParserJson(Properties properties) {

        urlICSA = properties.getProperty("ICSAUrl");
        urlIndexICSA = properties.getProperty("ICSAIndexUrl");
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

        Parser parser = new ICSAParserJson(prop);
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
        long start = System.currentTimeMillis() / 1000;
        long end;

        Model model = null;
        Model ModelAll = ModelFactory.createDefaultModel();

        // Step 1 - Downloading ICSA index resource from the internet...
        log.info("Downloading ICSA Index file from " + urlIndexICSA);
        String icsaIndexFileName = urlIndexICSA.substring(urlIndexICSA.lastIndexOf("/") + 1);
        String destICSAIndexFile = destDir + "/" + icsaIndexFileName;
        //String ICSAIndexFile = DownloadUnzip.downloadResource(urlIndexICSA, destICSAIndexFile);
        
        
        
        BufferedReader reader;

		try {
			reader = new BufferedReader(new FileReader(destICSAIndexFile));
			String line = reader.readLine();
			

			while (line != null) {
				 	String urlICSAfull = urlICSA+line;
				log.info("Downloading ICSA json file from " + urlICSAfull);
			        String icsaFileName = urlICSAfull.substring(urlICSAfull.lastIndexOf("/") + 1);
			        String destICSAFile = destDir + "/" + icsaFileName;
			        String ICSAFile = DownloadUnzip.downloadResource(urlICSAfull, destICSAFile);
			        System.out.print(ICSAFile);
				System.out.println(urlICSAfull);
				
				model = parseICSA(ICSAFile, rmlFile);
				 ModelAll.add(model);
				
				// read next line
				line = reader.readLine();
				
			}

			reader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
        
      //  System.exit(0);
        log.info("ICSA file downloaded");
       //ModelAll.write(System.out,"TURTLE");
        
        System.out.println("update ICSA");
     
    end = System.currentTimeMillis() / 1000;
    log.info("ICSA parser finished in " + (end - start) + " seconds");

    return ModelAll;
    }

    @Override public String saveModelToFile(Model model) {
        return Utility.saveToFile(model, outputDir, urlICSA);
    }

    @Override public void storeFileInRepo(String filename) {

        log.info("Store data to " + sparqlEndpoint + " using graph " + namegraph);
        storage.replaceData(filename, sparqlEndpoint, namegraph, isUseAuth, user, pass);
    }

    private Model parseICSA(String ICSAFile, String RMLFile) throws IOException {
        log.info("Parsing json to rdf...  ");
        Model icsaModel = JSONParser.Parse(ICSAFile, RMLFile);
        Integer countICSA = Utility.countInstance(icsaModel, ICSA.ICSA);
        log.info("The number of ICSA instances parsed: " + countICSA);
        log.info("Parsing done..!");
        return icsaModel;
    }

}
