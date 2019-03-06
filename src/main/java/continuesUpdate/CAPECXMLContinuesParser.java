package continuesUpdate;

import rmlparser.XMLParser;
import linkingGenerator.CVELinking3;
import linkingGenerator.CWELinking;
import linkingGenerator.CWELinking2;
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

public class CAPECXMLContinuesParser {
	
    public static void main(String[] args) throws Exception {
    	Properties prop =  new Properties();
    	FileInputStream ip= new FileInputStream("config.properties");
    	prop.load(ip);
    	parseCAPEC(prop);
    }
	
	public static void parseCAPEC(Properties prop) throws Exception{
	
    	//String urlCAPEC ="http://localhost/nvd/capec01/1000.xml.zip";
    	//String urlCAPEC ="http://localhost/nvd/capec02/1000.xml.zip";
    	//String urlCAPEC ="https://capec.mitre.org/data/xml/views/1000.xml.zip";
    	String urlCAPEC =prop.getProperty("CAPECUrl");
    	 //	String destDir = "D:/GDriveUndip/SEPSES/cyber-knowledgebase/jar/input/capecupdate";
    	 String destDir = prop.getProperty("InputDir")+"/capec";
    	//String outputDir = "D:/GDriveUndip/SEPSES/cyber-knowledgebase/jar/output/capec";
    	String outputDir = prop.getProperty("OutputDir")+"/capec";;
    	//String RMLFileTemp = "rml/nvdcapecnew-idc.rml";
    	String RMLFileTemp = prop.getProperty("CAPECRMLTempFile");
    	
    	//String RMLFile = "rml/nvdcapecnew-xml.rml";
    	String RMLFile = prop.getProperty("CAPECRMLFile");
    	//System.out.println(RMLFile);
		//String CyberKnowledgeEp = "http://localhost:8890/sparql";
    	String CyberKnowledgeEp = prop.getProperty("SparqlEndpoint");
    	//String namegraph = "http://localhost:8890/sepses/capec";
    	String namegraph = prop.getProperty("CAPECNamegraph");
    	String active = prop.getProperty("CAPECActive");
		
    	//===========================================
        //0. Check if the system active
    	System.out.println("time_start: "+new Date());  
    	if(!active.equals("Yes")) {
    		System.out.println("Sorry, CAPEC Parser is inactive.. please activate it in the config file !");
    		
    	}else {
    	
    	//1. Downloading CAPEC resource from the internet...
    	System.out.print("Downloading resource from "+urlCAPEC);
	    	String capecfileName = urlCAPEC.substring(urlCAPEC.lastIndexOf("/") + 1);
	    	String destCAPECFile = destDir+"/"+capecfileName;
	   		 String CAPECZipFile = DownloadUnzip.downloadResource(urlCAPEC, destCAPECFile);
	    System.out.println("  Done!");
		
	    //2. Unziping resource...
		System.out.print("Unzipping resource to...  ");
	    	String UnzipFile = DownloadUnzip.unzip(CAPECZipFile, destDir);
	    	//System.exit(0);
	    System.out.println(UnzipFile+"  Done!");
    	
	    //3. Injecting xml file...
	   // System.out.print("Injecting xml file...  ");
		    String CAPECXML = UnzipFile;
	    	String fileName = CAPECXML.substring(CAPECXML.lastIndexOf("/") + 1);
	        if(fileName.indexOf("\\")>=0) {
	        	 fileName = CAPECXML.substring(CAPECXML.lastIndexOf("\\") + 1);
	        }
	    	System.out.println(fileName);
	    	Path path = Paths.get(CAPECXML);
	    	Charset charset = StandardCharsets.UTF_8;
	    	String content = new String(Files.readAllBytes(path), charset);
	    	content = content.replaceAll("xmlns=\"http://capec.mitre.org/capec-3\"", "xmlns:1=\"http://capec.mitre.org/capec-3\"");
	    	Files.write(path, content.getBytes(charset));
	    	//System.exit(0);
	    	
	   // System.out.println("Done!");
	    
	 	   //4.0 Checking is uptodate...
		    System.out.println("Checking update from "+CyberKnowledgeEp+" using graphname "+namegraph);
		    boolean cat = CAPECUpdate.checkIsUptodate(RMLFileTemp,CAPECXML, CyberKnowledgeEp, namegraph);
	        if(cat) {
	        	 System.out.println("CAPEC is up-to-date...! ");
	        	 System.out.println("time_end: "+new Date());  
	        }else {
	        	 System.out.print("CAPEC is new...! ");
	        	
			    //4. Parsing xml to rdf......
			    System.out.println("Parsing xml to rdf...  ");  
			     parseCAPEC(CAPECXML,RMLFile, CyberKnowledgeEp,namegraph, outputDir);    
			    System.out.println("Done!");
			    //System.exit(0);
			    
			    //5. Storing data to triple store....
			    System.out.println("Storing data to triple store "+CyberKnowledgeEp+" using graphname"+namegraph);
		    	String output = outputDir+"/"+fileName+"-output.ttl";
		    	System.out.println(output);
			    Curl.storeInitData(output,namegraph);  
			    System.out.println("Done!");
			    //Finish
			    System.out.println("time_end: "+new Date());  
	        } 	 	
    	}
	}


    

    
    
   
    public static void parseCAPEC(String CAPECXMLFile, String RMLFile, String CyberKnowledgeEp, String graphname, String outputDir) throws Exception {

        String fileName = CAPECXMLFile.substring(CAPECXMLFile.lastIndexOf("/") + 1);
        //System.out.println(fileName);System.exit(0);
        if(fileName.indexOf("\\")>=0) {
        	 fileName = CAPECXMLFile.substring(CAPECXMLFile.lastIndexOf("\\") + 1);
        }
        org.apache.jena.rdf.model.Model CAPECModel = XMLParserJena.Parse(CAPECXMLFile, RMLFile);
        
        
        
    
       // CAPECModel.write(System.out,"TURTLE"); //System.exit(0);
        
        String CAPEC = CAPECUpdate.countCAPEC(CAPECModel);
        System.out.println("CAPEC parsed: "+CAPEC.toString());
               
        Curl.produceOutputFile(CAPECModel, outputDir, fileName);
        
        System.out.println("Parsing done..!");
    }
    

}
    

    
 
        

    


    
   


