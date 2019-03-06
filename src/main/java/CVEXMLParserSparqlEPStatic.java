
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
import org.apache.jena.vocabulary.RDFS;
import org.eclipse.rdf4j.common.io.IOUtil;
import org.eclipse.rdf4j.model.Model;
import org.eclipse.rdf4j.rio.RDFFormat;
import org.eclipse.rdf4j.rio.Rio;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class CVEXMLParserSparqlEPStatic {

    public static void main(String[] args) throws Exception {
    	
    	
    	//============Configuration and URL================
    	
    	String CVEXMLInput = "./input/staticcve/problem/nvdcve-2.0-2015.0.xml";
    	String outputDir = "./input/cveupdate";
    	String RMLFile = "rml/nvdcvenew-complete.rml";
    	String RDFOutput = "./output/staticcve";
		String CyberKnowledgeEp = "http://localhost:8890/sparql";
		String namegraph = "http://localhost:8890/sepses/cve";
		String CWEGraphName = "http://localhost:8890/sepses/cwe";
		String CPEGraphName = "http://localhost:8890/sepses/cpe";
		
    	//===========================================

	    //1. Parsing xml to rdf......
	    System.out.println("Parsing xml to rdf...  ");	    	
	    	parseCVE(CVEXMLInput,RMLFile,RDFOutput,CyberKnowledgeEp, CWEGraphName, CPEGraphName, outputDir);
	    System.out.println("Done!");
	    
	    //5. Storing data to triple store....
    	System.out.print("Storing data to triple store....  ");
    	String fileName = CVEXMLInput.substring(CVEXMLInput.lastIndexOf("/") + 1);
	    	String output = RDFOutput+"/"+fileName+"-output.ttl";
	    Curl.storeData(output,namegraph);
	    System.out.println("Done!");
	    //Finish
	    System.out.println("System Exit!");
	   // Sound.playSound();
	    //	}	   	
    	
    }
    
    public static void parseCVE(String CVEXMLFile, String RMLFile, String RDFOutput, String CyberKnowledgeEp, String CWEGraphName, String CPEGraphName, String outputDir) throws Exception {

        //String xmlFileName = "./input/cvedecade/cve-sample.xml";
        String fileName = CVEXMLFile.substring(CVEXMLFile.lastIndexOf("/") + 1);
        //System.out.println(fileName);System.exit(0);
        org.apache.jena.rdf.model.Model CVEModel = XMLParserJena.Parse(CVEXMLFile, RMLFile);  
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
    	
    	//join model
    	org.apache.jena.rdf.model.Model allCVE = CVEModel.union(CVETOCWE).union(CVETOCPE);   	
    	
    	//get an output file out of the model
    	String allCVEfileName = RDFOutput+"/"+fileName+"-output.ttl";
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


    
   


