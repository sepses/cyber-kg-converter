package ac.at.tuwien.ifs.sepses;

import ac.at.tuwien.ifs.sepses.update.helper.Curl;
import ac.at.tuwien.ifs.sepses.update.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.linking.CVELinking3;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.RDF;
import ac.at.tuwien.ifs.sepses.rml.XMLParserJena;

import java.io.FileWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class CVEXMLParserSparqlEP {

    public static void main(String[] args) throws Exception {

        //============Configuration and URL================
        //String urlCVE = "https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-modified.xml.zip";
        String urlCVE = "http://localhost/nvd/nvd02/nvdcve-2.0-modified.xml.zip";
        //String urlCVEMeta = "https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-modified.meta";
        String urlCVEMeta = "http://localhost/nvd/nvd02/nvdcve-2.0-modified.meta";
        String destDir = "./input/cveupdate";
        String outputDir = "./ouput/cveupdate";
        String RMLFile = "rml/nvdcvenew-complete.rml";
        String CyberKnowledgeEp = "http://localhost:8890/sparql";
        String namegraph = "http://localhost:8890/sepses/cve";
        String CWEGraphName = "http://localhost:8890/sepses/cwe";
        String CPEGraphName = "http://localhost:8890/sepses/cpe";

        //===========================================
        //0. Checking CVE Meta...
        System.out.print("Checking CVE Meta from the internet...  ");
        String metafileName = urlCVEMeta.substring(urlCVEMeta.lastIndexOf("/") + 1);
        //download meta and save temporarily to compare the current meta ac.at.tuwien.ifs.sepses.update with the last one
        String tempMetaDir = destDir + "/" + metafileName + ".temp";
        String currentMeta = DownloadUnzip.downloadResource(urlCVEMeta, tempMetaDir);
        Path currentMetaPath = Paths.get(currentMeta);
        String currentMetaContent = new String(Files.readAllBytes(currentMetaPath), StandardCharsets.UTF_8);
        //System.out.println(currentMetaContent);
        //lookup last meta
        String lastMeta = destDir + "/" + metafileName;
        Path lastMetaPath = Paths.get(lastMeta);
        String lastMetaContent = new String(Files.readAllBytes(lastMetaPath), StandardCharsets.UTF_8);
        //System.out.println(lastMetaContent);

        if (currentMetaContent.equals(lastMetaContent)) {
            System.out.println("CVE is already up-to-date!");
            System.exit(0);
        } else {
            System.out.println("CVE is New!");
            DownloadUnzip.downloadResource(urlCVEMeta, lastMeta);

            //1. Downloading CVE resource from the internet...
            System.out.print("Downloading resource from internet...  ");
            String cvefileName = urlCVE.substring(urlCVE.lastIndexOf("/") + 1);
            String destCVEFile = destDir + "/" + cvefileName;
            String CVEZipFile = DownloadUnzip.downloadResource(urlCVE, destCVEFile);
            System.out.println("Done!");

            //2. Unziping resource...
            System.out.print("Unzipping resource to...  ");
            String UnzipFile = DownloadUnzip.unzip(CVEZipFile, destDir);
            //System.exit(0);
            System.out.println(UnzipFile + "  Done!");

            //3. Injecting xml file...
            // System.out.print("Injecting xml file...  ");
            String CVEXML = UnzipFile;
            String fileName = CVEXML.substring(CVEXML.lastIndexOf("\\") + 1);
            Path path = Paths.get(CVEXML);
            Charset charset = StandardCharsets.UTF_8;
            String content = new String(Files.readAllBytes(path), charset);
            content = content.replaceAll("xmlns=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\"",
                    "xmlns:1=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\"");
            Files.write(path, content.getBytes(charset));
            //System.exit(0);
            // System.out.println("Done!");

            //4. Parsing xml to rdf......
            System.out.println("Parsing xml to rdf...  ");

            parseCVE(CVEXML, RMLFile, CyberKnowledgeEp, CWEGraphName, CPEGraphName, outputDir);
            System.out.println("Done!");

            //5. Storing data to triple store....
            System.out.print("Storing data to triple store....  ");
            String output = "output/" + fileName + "-output.ttl";
            Curl.storeData(output, namegraph);
            System.out.println("Done!");
            //Finish
            System.out.println("System Exit!");
        }

    }

    public static void parseCVE(String CVEXMLFile, String RMLFile, String CyberKnowledgeEp, String CWEGraphName,
            String CPEGraphName, String outputDir) throws Exception {

        //String xmlFileName = "./input/cvedecade/nvdcve-2.0-2018.xml";
        String fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("\\") + 1);
        //System.out.println(fileName);System.exit(0);
        org.apache.jena.rdf.model.Model CVEModel = XMLParserJena.Parse(CVEXMLFile, RMLFile);
        //CVEModel.write(System.out,"TURTLE");System.exit(0);    
        org.apache.jena.rdf.model.Model CVETOCPE =
                CVELinking3.generateLinkingCVETOCPE(CVEModel, CyberKnowledgeEp, CPEGraphName, fileName, outputDir);
        org.apache.jena.rdf.model.Model CVETOCWE =
                CVELinking3.generateLinkingCVETOCWE(CVEModel, CyberKnowledgeEp, CWEGraphName, fileName, outputDir);
        //remove unnecessary triples (literal cpeId & cweId)
        Property cpeId = CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cve#cpeId");
        Property cweId = CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cve#cweId");
        Property hasVulnerableConfiguration =
                CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cve#hasVulnerableConfiguration");
        Property hasLogicalTest = CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTest");
        Property logicalTestFactRef =
                CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cpe#logicalTestFactRef");
        Property logicalTestOperator =
                CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cpe#logicalTestOperator");
        Property logicalTestNegate =
                CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cpe#logicalTestNegate");
        Resource LogicalTest = CVEModel.createResource("http://w3id.org/sepses/vocab/ref/cpe#LogicalTest");
        CVEModel.removeAll(null, cpeId, null);
        CVEModel.removeAll(null, hasLogicalTest, null);
        CVEModel.removeAll(null, logicalTestFactRef, null);
        CVEModel.removeAll(null, logicalTestOperator, null);
        CVEModel.removeAll(null, logicalTestNegate, null);
        CVEModel.removeAll(null, cweId, null);
        CVEModel.removeAll(null, hasVulnerableConfiguration, null);
        CVEModel.removeAll(null, RDF.type, LogicalTest);
        //join the model
        org.apache.jena.rdf.model.Model allCVE = CVEModel.union(CVETOCWE).union(CVETOCPE);

        //get an output file out of the model
        String allCVEfileName = "output/" + fileName + "-output.ttl";
        //String cveModelfileName = "output/"+fileName+"-output-basic.ttl";
        FileWriter out = new FileWriter(allCVEfileName);
        // FileWriter out = new FileWriter(cveModelfileName);
        try {
            allCVE.write(out, "TURTLE");
            //CVEModel.write(out,"TURTLE");
        } finally {
            CVEModel.close();
            CVETOCPE.close();
            CVETOCWE.close();
        }
    }

}


    
   


