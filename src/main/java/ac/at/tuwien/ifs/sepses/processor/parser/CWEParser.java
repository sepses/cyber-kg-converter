package ac.at.tuwien.ifs.sepses.processor.parser;

import ac.at.tuwien.ifs.sepses.rml.XMLParser;
import ac.at.tuwien.ifs.sepses.processor.updater.CWEUpdate;
import ac.at.tuwien.ifs.sepses.processor.helper.Curl;
import ac.at.tuwien.ifs.sepses.processor.helper.DownloadUnzip;
import org.apache.jena.rdf.model.Property;

import java.io.FileInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.Properties;

public class CWEParser {

    public static void main(String[] args) throws Exception {
        Properties prop = new Properties();
        FileInputStream ip = new FileInputStream("config.properties");
        prop.load(ip);
        parseCWE(prop);

    }

    public static void parseCWE(Properties prop) throws Exception {

        //String urlCWE ="http://localhost/nvd/cwe03/1000.xml.zip";
        //String urlCWE ="http://localhost/nvd/cwe02/1000.xml.zip";
        //String urlCWE ="https://cwe.mitre.org/data/xml/views/1000.xml.zip";
        //String urlCWE = "https://cwe.mitre.org/data/xml/cwec_v3.0.xml.zip";
        String urlCWE = prop.getProperty("CWEUrl");
        //String destDir = "./input/cweupdate";
        String destDir = prop.getProperty("InputDir") + "/cwe";
        //String outputDir = "output/cwe/";
        String outputDir = prop.getProperty("OutputDir") + "/cwe";
        //String RMLFileTemp = "rml/nvdcwenew-idc.rml";
        String RMLFileTemp = prop.getProperty("CWERMLTempFile");
        //String RMLFileTemp = "rml/nvdcwenew-idc.rml";
        String RMLFile = prop.getProperty("CWERMLFile");
        //String CyberKnowledgeEp = "http://localhost:8890/sparql";
        String CyberKnowledgeEp = prop.getProperty("SparqlEndpoint");
        //String namegraph = "http://localhost:8890/sepses/cwe31";
        String namegraph = prop.getProperty("CWENamegraph");
        String CAPECGraphName = prop.getProperty("CAPECNamegraph");
        String active = prop.getProperty("CWEActive");

        //===========================================
        //0. Check if the system active
        System.out.println("time_start: " + new Date());
        if (!active.equals("Yes")) {
            System.out.println("Sorry, CWE Parser is inactive.. please activate it in the config file !");

        } else {

            //1. Downloading CWE resource from the internet...
            System.out.print("Downloading resource from " + urlCWE);
            String cwefileName = urlCWE.substring(urlCWE.lastIndexOf("/") + 1);
            String destCWEFile = destDir + "/" + cwefileName;
            String CWEZipFile = DownloadUnzip.downloadResource(urlCWE, destCWEFile);
            System.out.println("  Done!");

            //2. Unziping resource...
            System.out.print("Unzipping resource to...  ");
            String UnzipFile = DownloadUnzip.unzip(CWEZipFile, destDir);
            //System.exit(0);
            System.out.println(UnzipFile + "  Done!");

            //3. Injecting xml file...
            // System.out.print("Injecting xml file...  ");
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
            //System.exit(0);
            // System.out.println("Done!");

            //4.0 Checking is uptodate...
            System.out.println(
                    "Checking ac.at.tuwien.ifs.sepses.processor from " + CyberKnowledgeEp + " using graphname "
                            + namegraph);
            boolean cat = CWEUpdate.checkIsUptodate(RMLFileTemp, CWEXML, CyberKnowledgeEp, namegraph);
            if (cat) {
                System.out.println("CWE is up-to-date...! ");
                System.out.println("time_end: " + new Date());
            } else {
                System.out.print("CWE is new...! ");

                //4. Parsing xml to rdf......
                System.out.println("Parsing xml to rdf...  ");
                parseCWE(CWEXML, RMLFile, CyberKnowledgeEp, CAPECGraphName, namegraph, outputDir);
                System.out.println("Done!");
                //System.exit(0);

                //5. Storing data to triple store....
                System.out
                        .println("Storing data to triple store " + CyberKnowledgeEp + " using graphname" + namegraph);
                String output = outputDir + "/" + fileName + "-output.ttl";
                Curl.storeInitData(output, namegraph);
				    /*System.exit(0);
			   	
				    	if(c.equals("0")) {
				    		System.out.println("insert initial data");
				    		 Curl.storeInitData(output,namegraph);
				    	}else {
				    		System.out.println("ac.at.tuwien.ifs.sepses.processor data");
				    		 //ac.at.tuwien.ifs.sepses.processor the generator
				    	    // Curl.storeData(output,namegraph);
				    		 Curl.storeInitData(output,namegraph);
				    	}*/
                System.out.println("Done!");
                //Finish
                System.out.println("time_end: " + new Date());

            }
        }
    }

    public static void parseCWE(String CWEXMLFile, String RMLFile, String CyberKnowledgeEp, String CAPECGraphName,
            String graphname, String outputDir) throws Exception {

        String fileName = CWEXMLFile.substring(CWEXMLFile.lastIndexOf("/") + 1);
        if (fileName.indexOf("\\") >= 0) {
            fileName = CWEXMLFile.substring(CWEXMLFile.lastIndexOf("\\") + 1);
        }
        //System.out.println(fileName);

        org.apache.jena.rdf.model.Model CWEModel = XMLParser.Parse(CWEXMLFile, RMLFile);

        org.apache.jena.rdf.model.Model CWELinking = ac.at.tuwien.ifs.sepses.linking.CWELinking
                .generateLinking(CWEModel, CyberKnowledgeEp, CAPECGraphName, fileName, outputDir);

        CWEModel = CWEModel.union(CWELinking);
        Property capecId = CWEModel.createProperty("http://w3id.org/sepses/vocab/ref/cwe#capecId");
        CWEModel.removeAll(null, capecId, null);
        // CWEModel.write(System.out,"TURTLE");
        // System.exit(0);
        String cwe = CWEUpdate.countCWE(CWEModel);
        System.out.println("CWE parsed: " + cwe.toString());
        Curl.produceOutputFile(CWEModel, outputDir, fileName);
        System.out.println("Parsing done..!");

    }

}
    

    
 
        

    


    
   


