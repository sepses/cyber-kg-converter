package ac.at.tuwien.ifs.sepses.parser;

import ac.at.tuwien.ifs.sepses.helper.Curl;
import ac.at.tuwien.ifs.sepses.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.helper.QueryUtility;
import ac.at.tuwien.ifs.sepses.parser.tool.Linker;
import ac.at.tuwien.ifs.sepses.rml.XMLParser;
import ac.at.tuwien.ifs.sepses.vocab.CWE;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.Property;
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

public class CWEParser {

    private static final Logger log = LoggerFactory.getLogger(CWEParser.class);

    public static void main(String[] args) throws Exception {
        Properties prop = new Properties();
        FileInputStream ip = new FileInputStream("config.properties");
        prop.load(ip);
        parseCWE(prop);
    }

    public static void parseCWE(Properties prop) throws Exception {

        String urlCWE = prop.getProperty("CWEUrl");
        String destDir = prop.getProperty("InputDir") + "/cwe";
        String outputDir = prop.getProperty("OutputDir") + "/cwe";
        String RMLFileTemp = prop.getProperty("CWERMLTempFile");
        String RMLFile = prop.getProperty("CWERMLFile");
        String endpoint = prop.getProperty("SparqlEndpoint");
        String namegraph = prop.getProperty("CWENamegraph");
        String active = prop.getProperty("CWEActive");

        Boolean isUseAuth = Boolean.parseBoolean(prop.getProperty("UseAuth"));
        String user = prop.getProperty("EndpointUser");
        String pass = prop.getProperty("EndpointPass");

        // timer
        long start = System.currentTimeMillis() / 1000;
        long end;

        //===========================================
        // Step 0 - Check if the system active
        log.info("time_start: " + new Date());
        if (!active.equals("Yes")) {
            log.warn("Sorry, CWE Parser is inactive.. please activate it in the config file !");

        } else {
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
            Charset charset = StandardCharsets.UTF_8;
            String content = new String(Files.readAllBytes(path), charset);
            content = content.replaceAll("xmlns=\"http://cwe.mitre.org/cwe-6\"",
                    "xmlns:1=\"http://cwe.mitre.org/cwe-6\"");
            Files.write(path, content.getBytes(charset));
            log.info("... done!");

            // Step 4 - Checking whether the current CWE content is up-to-date...
            log.info("Checking updates from " + endpoint + " using graphname " + namegraph);
            boolean cat =
                    QueryUtility.checkIsUpToDate(RMLFileTemp, CWEXML, endpoint, namegraph, CWE.WEAKNESS_CATALOG);
            if (cat) {
                log.info("CWE is up-to-date...! ");

            } else {
                // Step 5 - Parsing xml to rdf......
                log.info("The downloaded CWE data is new...! ");
                String outputFile = parseCWE(CWEXML, RMLFile, outputDir);

                // Step 6 - Storing data to triple store....
                log.info("Storing data to triple store " + endpoint + " using graphname" + namegraph);
                Curl.storeData(outputFile, namegraph, endpoint, isUseAuth, user, pass);
            }

            end = System.currentTimeMillis() / 1000;
            log.info("CWE processing finished in " + (end - start) + " seconds");
        }
    }

    public static String parseCWE(String cweXmlFile, String rmlFile, String outputDir) throws Exception {
        log.info("Parsing xml to rdf...  ");

        String fileName = cweXmlFile.substring(cweXmlFile.lastIndexOf("/") + 1);
        if (fileName.indexOf("\\") >= 0) {
            fileName = cweXmlFile.substring(cweXmlFile.lastIndexOf("\\") + 1);
        }

        Model cweModel = XMLParser.Parse(cweXmlFile, rmlFile);
        Linker.updateCweLinks(cweModel);

        Integer cweCount = QueryUtility.countInstance(cweModel, CWE.CWE);
        log.info("The number of CWE instances parsed: " + cweCount);
        log.info("Parsing done..!");
        return Curl.produceOutputFile(cweModel, outputDir, fileName);
    }

}
    

    
 
        

    


    
   


