package ac.at.tuwien.ifs.sepses.processor.parser;

import ac.at.tuwien.ifs.sepses.processor.helper.Curl;
import ac.at.tuwien.ifs.sepses.processor.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.processor.helper.QueryUtility;
import ac.at.tuwien.ifs.sepses.rml.XMLParser;
import ac.at.tuwien.ifs.sepses.vocab.CAPEC;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.Properties;

public class CAPECParser {

    private static final Logger log = LoggerFactory.getLogger(CAPECParser.class);

    public static void main(String[] args) throws Exception {
        Properties prop = new Properties();
        FileInputStream ip = new FileInputStream("config.properties");
        prop.load(ip);
        parseCAPEC(prop);
    }

    public static void parseCAPEC(Properties prop) throws Exception {

        String urlCAPEC = prop.getProperty("CAPECUrl");
        String destDir = prop.getProperty("InputDir") + "/capec";
        String outputDir = prop.getProperty("OutputDir") + "/capec";
        String RMLFileTemp = prop.getProperty("CAPECRMLTempFile");
        String RMLFile = prop.getProperty("CAPECRMLFile");
        String sparqlEndpoint = prop.getProperty("SparqlEndpoint");
        String namegraph = prop.getProperty("CAPECNamegraph");
        String active = prop.getProperty("CAPECActive");

        Boolean isUseAuth = Boolean.parseBoolean(prop.getProperty("UseAuth"));
        String user = prop.getProperty("EndpointUser");
        String pass = prop.getProperty("EndpointPass");

        //===========================================
        // TIMER
        long start = System.currentTimeMillis() / 1000;
        long end;

        // Step 0 - Check if the system active
        log.info("time_start: " + new Date());
        if (!active.equals("Yes")) {
            log.warn("Sorry, CAPEC Parser is inactive.. please activate it in the config file !");

        } else {
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
            Charset charset = StandardCharsets.UTF_8;
            String content = new String(Files.readAllBytes(path), charset);
            content = content.replaceAll("xmlns=\"http://capec.mitre.org/capec-3\"",
                    "xmlns:1=\"http://capec.mitre.org/capec-3\"");
            Files.write(path, content.getBytes(charset));

            // Step 4 - Checking whether CAPEC is up-to-date ...
            log.info("Checking updates from " + sparqlEndpoint + " using graphname " + namegraph);
            Boolean cat = QueryUtility
                    .checkIsUpToDate(RMLFileTemp, capecXML, sparqlEndpoint, namegraph, CAPEC.ATTACK_PATTERN_CATALOG);
            if (cat) {
                log.info("CAPEC is up-to-date...! ");

            } else {
                log.info("CAPEC is new...! ");

                //4. Parsing xml to rdf......
                String ttlFile = parseCAPEC(capecXML, RMLFile, outputDir);

                //5. Delete old data ...
                log.info("delete old CAPEC data from " + sparqlEndpoint + " on graph" + namegraph);
                Curl.dropGraph(namegraph, sparqlEndpoint);

                //6. Store new CAPEC data to triple store....
                log.info("Store data to " + sparqlEndpoint + " using graph" + namegraph);
                Curl.storeData(ttlFile, namegraph, sparqlEndpoint, isUseAuth, user, pass);
            }

            end = System.currentTimeMillis() / 1000;
            log.info("CAPEC processing finished in " + (end - start) + " seconds");
        }
    }

    public static String parseCAPEC(String CAPECXMLFile, String RMLFile, String outputDir) throws Exception {
        log.info("Parsing xml to rdf...  ");

        String fileName = CAPECXMLFile.substring(CAPECXMLFile.lastIndexOf("/") + 1);
        if (fileName.indexOf("\\") >= 0) {
            fileName = CAPECXMLFile.substring(CAPECXMLFile.lastIndexOf("\\") + 1);
        }
        org.apache.jena.rdf.model.Model CAPECModel = XMLParser.Parse(CAPECXMLFile, RMLFile);
        Integer countCAPEC = QueryUtility.countInstance(CAPECModel, CAPEC.CAPEC);
        log.info("The number of CAPEC instances parsed: " + countCAPEC);
        log.info("Parsing done..!");

        return Curl.produceOutputFile(CAPECModel, outputDir, fileName);
    }

}
    

    
 
        

    


    
   


