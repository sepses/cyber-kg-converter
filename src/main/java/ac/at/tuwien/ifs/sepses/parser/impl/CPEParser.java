package ac.at.tuwien.ifs.sepses.parser.impl;

import ac.at.tuwien.ifs.sepses.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.helper.Utility;
import ac.at.tuwien.ifs.sepses.helper.XMLParser;
import ac.at.tuwien.ifs.sepses.parser.Parser;
import ac.at.tuwien.ifs.sepses.parser.tool.CPETool;
import ac.at.tuwien.ifs.sepses.storage.Storage;
import ac.at.tuwien.ifs.sepses.vocab.CPE;
import org.apache.commons.io.IOUtils;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.ResourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.topbraid.shacl.vocabulary.SH;

import java.io.*;
import java.nio.charset.Charset;
import java.util.Properties;

public class CPEParser implements Parser {

    private static final Logger log = LoggerFactory.getLogger(CPEParser.class);

    private final String urlCPE;
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

    public CPEParser(Properties properties) {

        urlCPE = properties.getProperty("CPEUrl");
        destDir = properties.getProperty("InputDir") + "/cpe";
        outputDir = properties.getProperty("OutputDir") + "/cpe";
        rmlMetaModel = properties.getProperty("CPERMLTempFile");
        rmlFile = properties.getProperty("CPERMLFile");
        namegraph = properties.getProperty("CPENamegraph");
        active = properties.getProperty("CPEActive");

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

        Parser parser = new CPEParser(prop);
        parser.parse(false);

    }

    @Override public void parse(Boolean isShaclActive) throws IOException {

        if (!active.equals("Yes")) {
            log.info("Sorry, CPE Parser is inactive.. please activate it in the config file !");

        } else {
            Model model = getModelFromLastUpdate();
            if (isShaclActive) {
                Model checkResults = Utility.validateWithShacl("shacl/cpe.ttl", model);
                if (checkResults.contains(null, SH.conforms, ResourceFactory.createTypedLiteral(false))) {
                    throw new IOException("CPE Validation Error: " + checkResults.toString());
                }
                checkResults.close();
                log.info("CPE Validation Succeeded");
            } else if (!model.isEmpty()) {
                String filename = saveModelToFile(model);
                storeFileInRepo(filename);
                model.close();
                addEmptyCPEComments();
            }
        }

    }

    private void addEmptyCPEComments() {
        try {
            log.info("add CPE-is-not-available-comment process");
            InputStream is = CVEParser.class.getClassLoader().getResourceAsStream("sparql/add-cpe-comments.sparql");
            String query = IOUtils.toString(is, Charset.forName("UTF-8"));
            is.close();
            storage.executeUpdate(sparqlEndpoint, query, isUseAuth, user, pass);
        } catch (IOException e) {
            log.error("failed add CPE-is-not-available-comment to graph: " + namegraph, e);
        }
        log.info("add CPE-is-not-available-comment process finished");
    }

    @Override public Model getModelFromLastUpdate() throws IOException {
        Model model = null;
        long start = System.currentTimeMillis() / 1000;
        long end;

        //1. Downloading CPE resource from the internet...
        log.info("Downloading resource from " + urlCPE);
        String cpefileName = urlCPE.substring(urlCPE.lastIndexOf("/") + 1);
        String destCPEFile = destDir + "/" + cpefileName;
        String CPEZipFile = DownloadUnzip.downloadResource(urlCPE, destCPEFile);
        log.info("   Done!");

        //2. Unziping resource...
        log.info("Unzipping resource to...  ");
        String UnzipFile = DownloadUnzip.unzip(CPEZipFile, destDir);
        log.info(UnzipFile + "  Done!");

        //3. Injecting xml file...
        log.info("Injecting xml file...  ");
       // String CPEXML = UnzipFile;
      String CPEXML = "input/cpe/official-cpe-dictionary_v2.3.xml";
        String fileName = CPEXML.substring(CPEXML.lastIndexOf("/") + 1);
        if (fileName.indexOf("\\") >= 0) {
            fileName = CPEXML.substring(CPEXML.lastIndexOf("\\") + 1);
        }
        	

        try {
            String co = null;
            StringBuffer inputBuffer = new StringBuffer();
            int c = 0;

            InputStream fis = new FileInputStream(CPEXML);
            InputStreamReader isr = new InputStreamReader(fis);
            BufferedReader reader = new BufferedReader(isr);
            while ((co = reader.readLine()) != null) {
                c++;
                if (c == 2) {
                    co = co.replaceAll("xmlns:1=\"http://cpe.mitre.org/dictionary/2.0\"",
                            "xmlns:c=\"http://cpe.mitre.org/dictionary/2.0\"");
                }
                inputBuffer.append(co);
                inputBuffer.append('\n');
            }
            reader.close();
            isr.close();
            fis.close();

            String inputStr = inputBuffer.toString();
            FileWriter fw = new FileWriter(CPEXML);
            BufferedWriter bw = new BufferedWriter(fw);
            log.info("write xml file");
            bw.write(inputStr);
            try {
                if (bw != null)
                    bw.close();
            } catch (Exception ex) {
                log.error("Error in closing the BufferedWriter; " + ex.getMessage(), ex);
            }
            bw.close();
            fw.close();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        log.info("Done!");

        //4. Checking ac.at.tuwien.ifs.sepses.processor...
        log.info("Checking updates from " + sparqlEndpoint + " using graphname " + namegraph);
        Integer cpeCount = Utility.countInstance(sparqlEndpoint, namegraph, CPE.CPE);
        log.info("existing cpe count = " + cpeCount);

        boolean sameVersion = Utility.checkIsEqualModifedDate(rmlMetaModel, CPEXML, sparqlEndpoint, namegraph,
                CPE.GENERATOR_TIME_STAMP);


        if (sameVersion) {
            log.info("CPE is up-to-date!!");
            model = ModelFactory.createDefaultModel();

        } else {
            log.info("CPE is NEW!!");
            //5. Parsing xml to rdf......
            log.info("Parsing xml to rdf...  ");
            model = parseCPE(CPEXML, rmlFile);
        }

        end = System.currentTimeMillis() / 1000;
        log.info("CPE processing finished in " + (end - start) + " seconds");

        return model;
    }

    @Override public String saveModelToFile(Model model) {
        return Utility.saveToFile(model, outputDir, urlCPE);
    }

    @Override public void storeFileInRepo(String filename) {

        log.info("Store data to " + sparqlEndpoint + " using graph " + namegraph);
        storage.replaceData(filename, sparqlEndpoint, namegraph, isUseAuth, user, pass);
    }

    private Model parseCPE(String CPEXMLFile, String RMLFile) throws IOException {

        Model CPEModel = XMLParser.Parse(CPEXMLFile, RMLFile);
        CPEModel.add(CPETool.generateAdditionalTriples(CPEModel));
        Integer count = Utility.countInstance(CPEModel, CPE.CPE);

        log.info("(new!) CPE parsed: " + count);
        log.info("Parsing done..!");

        return CPEModel;
    }
}
