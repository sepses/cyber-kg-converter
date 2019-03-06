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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Date;
import java.util.Properties;

public class CPEXMLContinuesParser {
	
    public static void main(String[] args) throws Exception {
    	Properties prop =  new Properties();
    	FileInputStream ip= new FileInputStream("config.properties");
    	prop.load(ip);
    	parseCPE(prop);
    }

    public static void parseCPE(Properties prop) throws Exception {
    	
    	//============Configuration and URL================
 
    	//String urlCPE = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip";
    	//String urlCPE = "http://localhost/nvd/cpe01/official-cpe-dictionary_v2.3.xml.zip";
    	///String urlCPE = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/archive-official-cpe-dictionary_v2.2-20190201-001524.xml.zip";
    	///String urlCPE = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/archive-official-cpe-dictionary_v2.2-20190202-001435.xml.zip";
    	///String urlCPE = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/archive-official-cpe-dictionary_v2.2-20190205-001339.xml.zip";
    	//String urlCPE ="https://nvd.nist.gov/feeds/xml/cpe/dictionary/archive-official-cpe-dictionary_v2.2-20190207-001556.xml.zip";
    	///String urlCPE ="https://nvd.nist.gov/feeds/xml/cpe/dictionary/archive-official-cpe-dictionary_v2.2-20190208-001606.xml.zip";
    	///String urlCPE = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/archive-official-cpe-dictionary_v2.2-20190209-001408.xml.zip";
    	///String urlCPE = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/archive-official-cpe-dictionary_v2.2-20190212-001634.xml.zip";
    	
    	String urlCPE =prop.getProperty("CPEUrl");
   	    String destDir = prop.getProperty("InputDir")+"/cpe";
   	    String outputDir = prop.getProperty("OutputDir")+"/cpe";;
   	    String RMLFileTemp = prop.getProperty("CPERMLTempFile");
   	    String RMLFile = prop.getProperty("CPERMLFile");
   	    String CyberKnowledgeEp = prop.getProperty("SparqlEndpoint");
   		String namegraph = prop.getProperty("CPENamegraph");
   		String active = prop.getProperty("CPEActive");
   	
	
    	//===========================================
   		//0. Check if the system active
   		System.out.println("time_start: "+new Date());  
    	if(!active.equals("Yes")) {
    		System.out.println("Sorry, CPE Parser is inactive.. please activate it in the config file !");
    		
    	}else {
   		
    	//1. Downloading CPE resource from the internet...
    	System.out.print("Downloading resource from "+urlCPE);
	    	String cpefileName = urlCPE.substring(urlCPE.lastIndexOf("/") + 1);
	    	String destCPEFile = destDir+"/"+cpefileName;
	   		 String CPEZipFile = DownloadUnzip.downloadResource(urlCPE, destCPEFile);
	    System.out.println("   Done!");
		
	    //2. Unziping resource...
		System.out.print("Unzipping resource to...  ");
	    	String UnzipFile = DownloadUnzip.unzip(CPEZipFile, destDir);
	    	//System.exit(0);
	    System.out.println(UnzipFile+"  Done!");
    	
	    //3. Injecting xml file...
	    System.out.print("Injecting xml file...  ");
		    String CPEXML = UnzipFile;
	    	String fileName = CPEXML.substring(CPEXML.lastIndexOf("/") + 1);
	    	   if(fileName.indexOf("\\")>=0) {
	          	 fileName = CPEXML.substring(CPEXML.lastIndexOf("\\") + 1);
	          }
	    	Path path = Paths.get(CPEXML);
	    	Charset charset = StandardCharsets.UTF_8;
	    	
	    	
	    	try {
	           
	            BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(CPEXML)));
	            String co=null;
	            StringBuffer inputBuffer = new StringBuffer();
	            int c=0;
	            while((co=reader.readLine())!=null)
	            {
	            	c++;
	            	if(c==2) {
	            	co = co.replaceAll("xmlns=\"http://cpe.mitre.org/dictionary/2.0\"", "xmlns:1=\"http://cpe.mitre.org/dictionary/2.0\"");
	                 
	            	}
	            	inputBuffer.append(co);
	                inputBuffer.append('\n');
	               
	            }
	            String inputStr = inputBuffer.toString();
	            FileWriter fw = new FileWriter(CPEXML);
	            BufferedWriter bw = new BufferedWriter(fw);
	            System.out.println("write xml file");
	            bw.write(inputStr);
	            try{
	      	      if(bw!=null)
	      		 bw.close();
	      	   }catch(Exception ex){
	      	       System.out.println("Error in closing the BufferedWriter"+ex);
	      	    }		    	
	        } catch (Exception e) {
	            // TODO Auto-generated catch block
	            e.printStackTrace();
	        }
	    System.out.println("Done!");
	    	
	    //4.0 Checking update...
	    System.out.println("Checking update from "+CyberKnowledgeEp+" using graphname "+namegraph);
	    String c = CPEUpdate.checkExistingTriple(CyberKnowledgeEp, namegraph);
        System.out.println("existing cpe = "+c);
        org.apache.jena.rdf.model.Model CPEModelTemp = XMLParserJena.Parse(CPEXML, RMLFileTemp);  
	    boolean sameVersion = CPEUpdate.checkingCPEVersion(CPEModelTemp, CyberKnowledgeEp, namegraph);
	        if(sameVersion) {
	        	System.out.println("CPE is up-to-date!!");
	        	System.out.println("time_end: "+new Date());  
	        }else {
	        	
	        	System.out.println("CPE is NEW!!");
			    //4. Parsing xml to rdf......
			    System.out.println("Parsing xml to rdf...  ");
			    boolean emptyTripleStore = parseCPE(CPEXML,RMLFile, CyberKnowledgeEp,namegraph, outputDir,c,CPEModelTemp);    	
			    //delete the generator
	        	CPEUpdate.deleteGenerator(CyberKnowledgeEp, namegraph);
			    System.out.println("Done!");
			   // System.exit(0);
			    
			    //5. Storing data to triple store....
		    	System.out.print("Storing data to triple store....  ");
			    	String output = outputDir+"/"+fileName+"-output.ttl";
			    	if(emptyTripleStore) {
			    		System.out.println("insert initial data");
			    		 Curl.storeInitData(output,namegraph);
			    	}else {
			    		System.out.println("update data");
			    		 //update the generator
			    		//System.out.println("delete old generator..!");
			    	     Curl.storeData(output,namegraph);
			    	}
			    System.out.println("Done!");
			    //Finish
			    System.out.println("time_end: "+new Date());  	
	      }
    	}
    }
    
    
   
    public static boolean parseCPE(String CPEXMLFile, String RMLFile, String CyberKnowledgeEp, String CPEGraphName, String outputDir, String c, org.apache.jena.rdf.model.Model cPEModelTemp) throws Exception {

        //String xmlFileName = "./input/cvedecade/nvdcve-2.0-2018.xml";
        String fileName = CPEXMLFile.substring(CPEXMLFile.lastIndexOf("/") + 1);
        if(fileName.indexOf("\\")>=0) {
       	 fileName = CPEXMLFile.substring(CPEXMLFile.lastIndexOf("\\") + 1);
       }
        //System.out.println(fileName);
        
        org.apache.jena.rdf.model.Model CPEModel = XMLParserJena.Parse(CPEXMLFile, RMLFile);
        String cpe = CPEUpdate.countCPE(CPEModel);
        org.apache.jena.rdf.model.Model addCPEModel = CPEUpdate.generateAdditionalTriples(CPEModel);
        System.out.println("CPE parsed: "+cpe.toString());
        
        org.apache.jena.rdf.model.Model allCPE = CPEModel.union(addCPEModel);
        allCPE = allCPE.union(cPEModelTemp);
        
        cPEModelTemp.close();
        addCPEModel.close();
        CPEModel.close();
        
        
        System.out.println("Parsing done..!");
        //allCPE.write(System.out,"TURTLE");
        
		//System.exit(0);
        if(c.equals("0")) {
			//dont update cpe model
        	//get an output file out of the model
        		System.out.println("produce turtle output file");
        		Curl.produceOutputFile(allCPE, outputDir, fileName);
            return true;
 		}else {
			//update cpe model
 			//System.out.print("generateAdditionalCPE");//System.exit(0);
 			//org.apache.jena.rdf.model.Model CPEModelx = CPEUpdate.generateAdditionalCPE(CPEModel,CyberKnowledgeEp, CPEGraphName);
			//System.exit(0);
 			//Curl.produceOutputFile(CPEModelx, outputDir, fileName);
 			System.out.println("produce turtle output file");
 			Curl.produceOutputFile(allCPE, outputDir, fileName);
			return false;
		}
 
    }
    

}
    

    
 
        

    


    
   


