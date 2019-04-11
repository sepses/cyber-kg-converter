package ac.at.tuwien.ifs.sepses.parser;

import ac.at.tuwien.ifs.sepses.helper.Curl;
import ac.at.tuwien.ifs.sepses.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.helper.QueryUtility;
import ac.at.tuwien.ifs.sepses.parser.tool.CPETool;
import ac.at.tuwien.ifs.sepses.rml.XMLParser;
import ac.at.tuwien.ifs.sepses.vocab.CPE;
import org.apache.jena.rdf.model.Model;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.Properties;

public class CPEParser {

    private static final Logger log = LoggerFactory.getLogger(CPEParser.class);

    public static void main(String[] args) throws Exception {
        Properties prop = new Properties();
        FileInputStream ip = new FileInputStream("config.properties");
        prop.load(ip);
        parseCPE(prop);
    }

    public static void parseCPE(Properties prop) throws Exception {

        //============Configuration and URL================

        String urlCPE = prop.getProperty("CPEUrl");
        String destDir = prop.getProperty("InputDir") + "/cpe";
        String outputDir = prop.getProperty("OutputDir") + "/cpe";

        String RMLFileTemp = prop.getProperty("CPERMLTempFile");
        String RMLFile = prop.getProperty("CPERMLFile");
        String sparqlEndpoint = prop.getProperty("SparqlEndpoint");
        String namegraph = prop.getProperty("CPENamegraph");
        String active = prop.getProperty("CPEActive");

        Boolean isUseAuth = Boolean.parseBoolean(prop.getProperty("UseAuth"));
        String username = prop.getProperty("EndpointUser");
        String password = prop.getProperty("EndpointPass");

        //===========================================
        //0. Check if the system active
        log.info("time_start: " + new Date());
        if (!active.equals("Yes")) {
            log.info("Sorry, CPE Parser is inactive.. please activate it in the config file !");

        } else {

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
            String CPEXML = UnzipFile;
            String fileName = CPEXML.substring(CPEXML.lastIndexOf("/") + 1);
            if (fileName.indexOf("\\") >= 0) {
                fileName = CPEXML.substring(CPEXML.lastIndexOf("\\") + 1);
            }
            Path path = Paths.get(CPEXML);
            Charset charset = StandardCharsets.UTF_8;

            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(CPEXML)));
                String co = null;
                StringBuffer inputBuffer = new StringBuffer();
                int c = 0;
                while ((co = reader.readLine()) != null) {
                    c++;
                    if (c == 2) {
                        co = co.replaceAll("xmlns=\"http://cpe.mitre.org/dictionary/2.0\"",
                                "xmlns:1=\"http://cpe.mitre.org/dictionary/2.0\"");
                    }
                    inputBuffer.append(co);
                    inputBuffer.append('\n');
                }
                String inputStr = inputBuffer.toString();
                FileWriter fw = new FileWriter(CPEXML);
                BufferedWriter bw = new BufferedWriter(fw);
                log.info("write xml file");
                bw.write(inputStr);
                try {
                    if (bw != null)
                        bw.close();
                } catch (Exception ex) {
                    log.error("Error in closing the BufferedWriter\n" + ex.getMessage(), ex);
                }
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
            log.info("Done!");

            //4.0 Checking ac.at.tuwien.ifs.sepses.processor...
            log.info("Checking updates from " + sparqlEndpoint + " using graphname " + namegraph);
            Integer cpeCount = QueryUtility.countInstance(sparqlEndpoint, namegraph, CPE.CPE);
            log.info("existing cpe count = " + cpeCount);

            long start = System.currentTimeMillis() / 1000;
            long end;
            boolean sameVersion = QueryUtility.checkIsEqualModifedDate(RMLFileTemp, CPEXML, sparqlEndpoint, namegraph,
                    CPE.GENERATOR_TIME_STAMP);
            if (sameVersion) {
                log.info("CPE is up-to-date!!");
                log.info("time_end: " + new Date());

            } else {
                log.info("CPE is NEW!!");
                //4. Parsing xml to rdf......
                log.info("Parsing xml to rdf...  ");
                String outputFile = parseCPE(CPEXML, RMLFile, outputDir);

                // Step 5 - Storing data to triple store....
                log.info("Storing data to triple store " + sparqlEndpoint + " using graphname " + namegraph);
                Curl.storeData(outputFile, namegraph, sparqlEndpoint, isUseAuth, username, password);
            }

            end = System.currentTimeMillis() / 1000;
            log.info("CPE processing finished in " + (end - start) + " seconds");
        }
    }

    public static String parseCPE(String CPEXMLFile, String RMLFile, String outputDir) throws Exception {

        String fileName = CPEXMLFile.substring(CPEXMLFile.lastIndexOf("/") + 1);
        if (fileName.indexOf("\\") >= 0) {
            fileName = CPEXMLFile.substring(CPEXMLFile.lastIndexOf("\\") + 1);
        }

        Model CPEModel = XMLParser.Parse(CPEXMLFile, RMLFile);
        CPEModel.add(CPETool.generateAdditionalTriples(CPEModel));
        Integer count = QueryUtility.countInstance(CPEModel, CPE.CPE);
        log.info("(new!) CPE parsed: " + count);

        log.info("Parsing done..!");
        log.info("produce turtle output file");
        return Curl.produceOutputFile(CPEModel, outputDir, fileName);
    }
}
