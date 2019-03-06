package continuesUpdate;

import rmlparser.XMLParser;
import linkingGenerator.CVELinking3;
import rmlparser.XMLParserJena;
import continuesUpdate.*;

import org.apache.commons.io.IOUtils;
import org.apache.http.impl.io.SocketOutputBuffer;
import org.apache.jena.rdf.model.*;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.vocabulary.RDF;
import org.eclipse.rdf4j.common.io.IOUtil;
import org.eclipse.rdf4j.model.Model;
import org.eclipse.rdf4j.rio.RDFFormat;
import org.eclipse.rdf4j.rio.Rio;

import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Date;
import java.util.Properties;

public class CVEXMLContinuesParser {
	
    public static void main(String[] args) throws Exception {
    	Properties prop =  new Properties();
    	FileInputStream ip= new FileInputStream("config.properties");
    	prop.load(ip);
    	parseCVE(prop);
    }

    public static void parseCVE(Properties prop) throws Exception {
    	
    	//============Configuration and URL================
    	//date 06/02/2019 @ 14:55
    	//String urlCVE = "https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-modified.xml.zip";
    	//String urlCVEMeta = "https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-modified.meta";

		
		String urlCVE =prop.getProperty("CVEUrl");
		String urlCVEMeta = prop.getProperty("CVEMetaUrl");
	   	String destDir = prop.getProperty("InputDir")+"/cve";
	   	String outputDir = prop.getProperty("OutputDir")+"/cve";;
	   	String RMLFileTemp = prop.getProperty("CVERMLTempFile");
	   	String RMLFile = prop.getProperty("CVERMLFile");
	   	String CyberKnowledgeEp = prop.getProperty("SparqlEndpoint");
	   	String namegraph = prop.getProperty("CVENamegraph");
	   	String CWEGraphName = prop.getProperty("CWENamegraph");
	   	String CPEGraphName = prop.getProperty("CPENamegraph");
	   	String active = prop.getProperty("CVEActive");
		
    	//===========================================
	   	System.out.println("time_start: "+new Date());  
   		//0. Check if the system active
    	if(!active.equals("Yes")) {
    		System.out.println("Sorry, CVE Parser is inactive.. please activate it in the config file !");
    		
    	}else {
	   	
        //0. Checking CVE Meta...
    	System.out.println("Checking resource meta from "+urlCVEMeta);
    	 	String metafileName = urlCVEMeta.substring(urlCVEMeta.lastIndexOf("/") + 1);
    	 	String metaDir = destDir+"/"+metafileName;
    		String currentMeta = DownloadUnzip.downloadResource(urlCVEMeta, metaDir);  
    		Path currentMetaPath = Paths.get(currentMeta);
    		String metaSHA = CVEUpdate.readMetaSHA(currentMetaPath.toString());
    		//System.out.println(metaSHA);System.exit(0);
    		boolean checkCVEMeta = CVEUpdate.checkSHAMeta(metaSHA, CyberKnowledgeEp, namegraph);
    		//System.out.println(checkCVEMeta);System.exit(0);
    		if(checkCVEMeta) {
    			System.out.println("  Resource is already up-to-date!");
	    		System.out.println("time_end: "+new Date()); 
    	 		    	}else {
	    		System.out.println("Resource is New!");
	    		org.apache.jena.rdf.model.Model CVEMetaModel = CVEUpdate.generateCVEMetaTriple(metaSHA);
	    		//CVEMetaModel.write(System.out,"TURTLE");System.exit(0);
	    		//DownloadUnzip.downloadResource(urlCVEMeta, lastMeta);
	    		//1. Downloading CVE resource from the internet...
	    		System.out.print("Downloading resource from internet...  ");
	    			String cvefileName = urlCVE.substring(urlCVE.lastIndexOf("/") + 1);
	    			String destCVEFile = destDir+"/"+cvefileName;
	    			String CVEZipFile = DownloadUnzip.downloadResource(urlCVE, destCVEFile);
	    		System.out.println("  Done!");
		
	    		//2. Unziping resource...
	    		System.out.print("Unzipping resource to...  ");
	    			String UnzipFile = DownloadUnzip.unzip(CVEZipFile, destDir);
	    			//System.exit(0);
	    		System.out.println(UnzipFile+"  Done!");
    	
	    		//3. Injecting xml file...
	    		// System.out.print("Injecting xml file...  ");
	    			String CVEXML = UnzipFile;
	    			String fileName = CVEXML.substring(CVEXML.lastIndexOf("/") + 1);
	    			   if(fileName.indexOf("\\")>=0) {
	    		        	 fileName = CVEXML.substring(CVEXML.lastIndexOf("\\") + 1);
	    		        }
	    			Path path = Paths.get(CVEXML);
	    			Charset charset = StandardCharsets.UTF_8;
	    			String content = new String(Files.readAllBytes(path), charset);
	    			content = content.replaceAll("xmlns=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\"", "xmlns:1=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\"");
	    			Files.write(path, content.getBytes(charset));
	    			//System.exit(0);
	    			// System.out.println("Done!");
	    	
	    		//4.0 Checking update...
	    		System.out.println("Checking update... ");
	    			
	    			parseTempCVE(CVEXML, RMLFileTemp, CyberKnowledgeEp, namegraph);
	    			System.out.println("Done!");	
	    
	    		//4. Parsing xml to rdf......
	    		System.out.print("Parsing xml to rdf...  "); 
	    			parseCVE(CVEXML,RMLFile, CyberKnowledgeEp, CWEGraphName, CPEGraphName, outputDir, CVEMetaModel);
	    		System.out.println("Done!");
	    
	    		//5. Storing data to triple store....
	    		System.out.print("Storing data to triple store....  ");
	    			String output = outputDir+"/"+fileName+"-output.ttl";
	    			//delete previous CVEMeta
	    			CVEUpdate.deleteCVEMeta(CyberKnowledgeEp, namegraph);
	    			Curl.storeData(output,namegraph);
	    			System.out.println("Done!");
	    			//Finish
	    			System.out.println("time_end: "+new Date());  
	    		}	   	
    	}
    }
    
    public static void parseTempCVE(String CVEXMLFile, String RMLFileTemp, String CyberKnowledgeEp, String CVEGraphName) throws Exception {

        //String xmlFileName = "./input/cvedecade/nvdcve-2.0-2018.xml";
        String fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("/") + 1);
		   if(fileName.indexOf("\\")>=0) {
	        	 fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("\\") + 1);
	        }
        //System.out.println(fileName);System.exit(0);
        org.apache.jena.rdf.model.Model CVEModelTemp = XMLParserJena.Parse(CVEXMLFile, RMLFileTemp);  
        //CVEModelTemp.write(System.out,"TURTLE");
    	ArrayList<String>[] CVEArray = CVEUpdate.checkExistingCVE(CVEModelTemp, CyberKnowledgeEp, CVEGraphName);
    	System.out.println("Done!");
    	System.out.println("Found New CVE: "+CVEArray[0].size());
    	System.out.println("Found modified CVE : "+CVEArray[1].size());
    	System.out.println("Found existing CVE : "+CVEArray[2].size());
    	if((CVEArray[0].size()==0) && (CVEArray[1].size()==0)) {
    		System.out.println("CVE is already updated");
    		//System.exit(0);
    	}
    	CVEModelTemp.close();
        
        
    }
    

    
    public static void parseCVE(String CVEXMLFile, String RMLFile, String CyberKnowledgeEp, String CWEGraphName, String CPEGraphName, String outputDir, org.apache.jena.rdf.model.Model CVEMetaModel) throws Exception {

        //String xmlFileName = "./input/cvedecade/nvdcve-2.0-2018.xml";
        String fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("/") + 1);
        if(fileName.indexOf("\\")>=0) {
       	 fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("\\") + 1);
       }
        //System.out.println(fileName);System.exit(0);
        org.apache.jena.rdf.model.Model CVEModel = XMLParserJena.Parse(CVEXMLFile, RMLFile);  
       //act to update
         
    	 System.out.println("Generate linking...");
    	//System.exit(0);
        //CVEModel.write(System.out,"TURTLE");System.exit(0);    
    	org.apache.jena.rdf.model.Model CVETOCPE = CVELinking3.generateLinkingCVETOCPE(CVEModel, CyberKnowledgeEp, CPEGraphName, fileName, outputDir);
    	org.apache.jena.rdf.model.Model CVETOCWE = CVELinking3.generateLinkingCVETOCWE(CVEModel, CyberKnowledgeEp, CWEGraphName, fileName, outputDir);    	
    	//remove unnecessary triples (literal cpeId & cweId)
    	Property cpeId = CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cve#cpeId");
    	Property cweId = CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cve#cweId");
    	Property hasVulnerableConfiguration = CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cve#hasVulnerableConfiguration");
    	Property hasLogicalTest = CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTest");
    	Property logicalTestFactRef = CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cpe#logicalTestFactRef");
    	Property logicalTestOperator = CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cpe#logicalTestOperator");
    	Property logicalTestNegate = CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cpe#logicalTestNegate");
    	Resource LogicalTest = CVEModel.createResource("http://w3id.org/sepses/vocab/ref/cpe#LogicalTest");
    	CVEModel.removeAll(null,cpeId, null);
    	CVEModel.removeAll(null,hasLogicalTest, null);
    	CVEModel.removeAll(null,logicalTestFactRef, null);
     	CVEModel.removeAll(null,logicalTestOperator, null);
     	CVEModel.removeAll(null,logicalTestNegate, null);
     	CVEModel.removeAll(null,cweId, null);
    	CVEModel.removeAll(null,hasVulnerableConfiguration, null);
    	CVEModel.removeAll(null,RDF.type,LogicalTest);
    	//join the model
    	
    	
    	//delete previous Meta model
    	
    	
    		
    	org.apache.jena.rdf.model.Model allCVE = CVEModel.union(CVETOCWE).union(CVETOCPE).union(CVEMetaModel);   	
    	
    	
    	//get an output file out of the model
    	String allCVEfileName = outputDir+"/"+fileName+"-output.ttl";
        //String cveModelfileName = "output/"+fileName+"-output-basic.ttl";
        FileWriter out = new FileWriter(allCVEfileName);
       // FileWriter out = new FileWriter(cveModelfileName);     
        try {
        	allCVE.write(out,"TURTLE");
        	//CVEModel.write(out,"TURTLE");     	
        }
        finally {
           CVEModel.close();	
		   CVETOCPE.close();
		   CVETOCWE.close();
        }
    }

        

    }


    
   


