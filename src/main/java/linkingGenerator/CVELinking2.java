package linkingGenerator;

import java.beans.Encoder;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;

import org.apache.jena.base.Sys;
import org.apache.jena.query.Query;
import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QueryFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;

import com.github.andrewoma.dexx.collection.internal.base.Break;

public class CVELinking2 {
	
	
	public static Model generateLinkingCVETOCPE(Model CVEModel, Model CPEModel, String fileName) throws IOException {
		
	//1. select all CVE subject
		String Query1 = "\r\n" + 
				"select ?s where {\r\n" + 
				"    ?s a <http://w3id.org/sepses/vocab/ref/cve#CVE> .\r\n" + 
				"}\r\n" + 
				"";
		//System.out.println(Query1);System.exit(0);
		
		Query Q1 = QueryFactory.create(Query1);
		QueryExecution Qex1 = QueryExecutionFactory.create(Q1, CVEModel);
	 	ResultSet QResult1 = Qex1.execSelect();
	 	Model linkingModelCVECPE = ModelFactory.createDefaultModel();
	 	Model NolinkingModelCVECPE = ModelFactory.createDefaultModel();
	 	String nolinking_cve_cpe = ""; 
	 	while (QResult1.hasNext()) {
			 QuerySolution QS1 = QResult1.nextSolution();
			 RDFNode cveId = QS1.get("?s");
			//System.out.println(cveId.toString());
	//2. for each subject result, select all CPE that the subject connect to
				
			 String Query2 = "select ?cpeId where {  \r\n" + 
			 			"?s <http://w3id.org/sepses/vocab/ref/cve#cpeId> ?cpeId. \r\n" + 
			 			"filter (?s = <"+cveId+">) . \r\n" + 
			 				"}"; 
			 
			 //System.out.println(Query2);
			 
			 Query Q2 = QueryFactory.create(Query2);
		     QueryExecution Qex2 = QueryExecutionFactory.create(Q2, CVEModel);
			 ResultSet QResult2 = Qex2.execSelect();
			 ArrayList<String> filterCPEArray = new ArrayList<String>();
			 String filterCPE="";
			 while (QResult2.hasNext()) {
				 QuerySolution QS2 = QResult2.nextSolution();
				 RDFNode cpeId = QS2.get("?cpeId"); 
			  filterCPE = filterCPE+"?cpeId = \""+cpeId.toString()+"\" || ";
			  filterCPEArray.add(cpeId.toString());
			 }
			// System.out.println(filterCPE);
	
			//4. keep result from 3 to an array
			 ArrayList<String>[] CPEArrayofList = getCPEResourceFilterStatement(filterCPE+"?cpeId = \"0\"", CPEModel);
				//System.out.println(CPEResArray);System.exit(0);
			 Property hasNoCPE = linkingModelCVECPE.createProperty("http://w3id.org/sepses/vocab/ref/cve#hasNoCPE"); 
				
			 //if CPE is empty or no linking to CPE at all
			 if(CPEArrayofList[0].size()==0) {
				 System.out.println(cveId+": CPE is empty, cpe= "+CPEArrayofList[0].size()+"& cpeInCVE ="+filterCPEArray.size());
				 int i = 0;
				 while(filterCPEArray.size()>i){
					 //nolinking_cve_cpe=cveId.toString()+",cpeId:"+filterCPEArray.get(i)+"\n"+nolinking_cve_cpe;
					  Resource resSn = NolinkingModelCVECPE.createResource(cveId.toString());
				      //Resource resOn = NolinkingModelCVECPE.createResource(filterCPEArray.get(i));
					  resSn.addProperty(hasNoCPE,filterCPEArray.get(i));
				   
					 //system.out
					 i++;
					}
				 //delete unnecessary triple
				 Property hasVulCon = CVEModel.createProperty("http://w3id.org/sepses/vocab/ref/cve#hasVulnerableConfiguration"); 
				 Resource cveIds = NolinkingModelCVECPE.createResource(cveId.toString());
				 CVEModel.removeAll(cveIds, hasVulCon, null);

				 
			 }else {
				 Property hasCPE = linkingModelCVECPE.createProperty("http://w3id.org/sepses/vocab/ref/cve#hasCPE"); 
				//if CVE has complete CPE linking 
				 if(filterCPEArray.size()==CPEArrayofList[0].size()) {
					 System.out.println(cveId+": CPE is complete, cpe ="+CPEArrayofList[0].size()+"& cpeInCVE ="+filterCPEArray.size());
					 int j = 0;
					 while(CPEArrayofList[0].size()>j){
						    Resource resS = linkingModelCVECPE.createResource(cveId.toString());
						      Resource resO = linkingModelCVECPE.createResource(CPEArrayofList[0].get(j));
							  resS.addProperty(hasCPE,resO);
						    j++;
						}
					
					  
				 }else {
					 //if CPE is not completely linking (partial linking to CVE)
					 System.out.println(cveId+": CPE is not complete, cpe ="+CPEArrayofList[0].size()+"& cpeInCVE ="+filterCPEArray.size());
									
					 
					 int k = 0;
					 while(CPEArrayofList[0].size()>k){
						 		  Resource resS = linkingModelCVECPE.createResource(cveId.toString());
						 		  Resource resO = linkingModelCVECPE.createResource(CPEArrayofList[0].get(k));
								  resS.addProperty(hasCPE,resO);
						    k++;
					 }
					 
					 int l = 0;
					 
					 //where CPE is not there
					 int m=0;
					 while(filterCPEArray.size()>l){
						 if (!CPEArrayofList[1].contains(filterCPEArray.get(l))) {
							 m++;
							 
									//   nolinking_cve_cpe=cveId.toString()+",cpeId:"+filterCPEArray.get(l)+"\n"+nolinking_cve_cpe;
									 // System.out.println(CVER.toString()+" has no linking !! ");  
									   Resource resSn = NolinkingModelCVECPE.createResource(cveId.toString());
									    //  Resource resOn = NolinkingModelCVECPE.createResource("http://example.org/sepses/cpe#"+filterCPEArray.get(l));
										  resSn.addProperty(hasNoCPE,filterCPEArray.get(l));
									   
								}
						    l++;
					}
					 System.out.println("difference ="+m);
					 
					 
					 
				 }
			 }
			 
	 	}
	 	
		 String fileNameNL = "output/linking/CVETOCPE_"+fileName+"_NoLinking.log.ttl";
	       // FileWriter rdfLingking = new FileWriter(fileName);
	        FileWriter nolinkingCVECPELog = new FileWriter(fileNameNL);
		      
	        try {
	       
	        	//nolinkingCVECPELog.write(nolinking_cve_cpe);
	        	NolinkingModelCVECPE.write(nolinkingCVECPELog,"TURTLE");
	        }
	        finally {
	            //linkingModel.close();
	             
	        }
			 
			 
			// System.exit(0);
	        
	 	
			
	 	
	 	return linkingModelCVECPE;
	}
			 
		
public static Model generateLinkingCVETOCWE(Model CVEModel, Model CWEModel,String fileName) throws IOException {
		
		//load and read the rdf snort Rule
	
		 //CVEModel.write(System.out,"TURTLE");System.exit(0);			
		//find the linking, if it exists generate linking otherwise make a log

	//query to get cweId property from CVE per year
   	String sidQuery3 = 
   			"select distinct ?cweId where { \r\n" + 
   			"    ?s <http://w3id.org/sepses/vocab/ref/cve#cweId> ?cweId .\r\n" + 
   			"} \r\n" + 
   			"";
   		
	String sidQuery4 = "select ?s ?cweId where { \r\n" + 
			"    ?s <http://w3id.org/sepses/vocab/ref/cve#cweId> ?cweId .\r\n" + 
			"} \r\n" + 
			"";
	
	//generate filter for CWE query	 
	 Query sidQ3 = QueryFactory.create(sidQuery3);
		QueryExecution sidQex3 = QueryExecutionFactory.create(sidQ3, CVEModel);
		 ResultSet sidQResult3 = sidQex3.execSelect();
		 String filterStatement2 = "";
		 while (sidQResult3.hasNext()) {
			 QuerySolution sidQS3 = sidQResult3.nextSolution();
			// RDFNode snortRuleRes = sidQS.get("s");
			 RDFNode CVECWE = sidQS3.get("cweId");
			 filterStatement2 = filterStatement2+"?cweId = \""+CVECWE.toString().substring(4)+"\" || ";
			  
		 }
		//System.out.println(filterStatement2);System.exit(0);
		 	 
	 	ArrayList<String>[] CWEResArray = getCWEResourceFilterStatement(filterStatement2+"?cweId = \"0\"", CWEModel);
			 
		//System.out.println(CWEResArray[0].size());//System.exit(0);
		//System.out.println(CWEResArray[1].size());System.exit(0);
		 //create linking CVE-CWE
		Query sidQ4 = QueryFactory.create(sidQuery4);
		QueryExecution sidQex4 = QueryExecutionFactory.create(sidQ4, CVEModel);
	 	ResultSet sidQResult4 = sidQex4.execSelect();
	 	
	 	//make new model for lingking cpe result 
	 	Model linkingModel = ModelFactory.createDefaultModel();
	 	Model NolinkingModel = ModelFactory.createDefaultModel();
	 	Property hasCWE = linkingModel.createProperty("http://w3id.org/sepses/vocab/ref/cwe#hasCWE"); 
	 	Property hasNoCWE = linkingModel.createProperty("http://w3id.org/sepses/vocab/ref/cwe#hasNoCWE"); 
	  //  String nolinking_cve_cwe = ""; 
	    int CWEFound=0;
	    int CWENotFound=0;
	    while (sidQResult4.hasNext()) {
			 QuerySolution sidQS4 = sidQResult4.nextSolution();
			 RDFNode CVERes4 = sidQS4.get("s");
			 RDFNode CVECWE4 = sidQS4.get("cweId");
			 //System.out.println(CVECWE4.toString());
			 int CWEfound=0; 
			 int i=0;
			 while(CWEResArray[1].size() > i) {	 	
				
				// i++;
			   if (CWEResArray[1].get(i).equals(CVECWE4.toString().substring(4))) {
				  //System.out.print(CWEResArray[1].get(i)+"|");System.out.println(CVECWE4.toString().substring(4)); 
				  Resource resS = linkingModel.createResource(CVERes4.toString());
				  Resource resO = linkingModel.createResource(CWEResArray[0].get(i));
				  resS.addProperty(hasCWE,resO);
				  CWEfound++;
				  System.out.println("CWE Found, generate linking "+CVERes4.toString()+"to "+CWEResArray[0].get(i));
				   // System.out.println(CWERes2.toString()+" "+lista);
				 
				}
			   i++;
			//  System.exit(0);
		      }
			 if(CWEfound < 1) {
				  Resource resSno = NolinkingModel.createResource(CVERes4.toString());
				  //Resource resOno = NolinkingModel.createResource(CVECWE4.toString());
				  resSno.addProperty(hasNoCWE,CVECWE4.toString());
				  System.out.println("CWE Not Found, generate No linking "+CVERes4.toString()+"to "+CVECWE4.toString());
			   CWENotFound++;  
			 }else {
			   CWEFound++;
			 }
			 }
	    System.out.println("CWE Found :"+CWEFound+", CWE Not Found : "+CWENotFound);
	    //System.exit(0);
			 
				 //linkingModel.write(System.out,"TURTLE"); 
				 
				 //String fileName = "output/linking/snortRuleToCVE.ttl";
				 String fileNameNL = "output/linking/CVETOCWE_"+fileName+"_NoLinking.log.ttl";
			       // FileWriter rdfLingking = new FileWriter(fileName);
			        FileWriter nolinkingCVECWELog = new FileWriter(fileNameNL);
				      
			        try {
			        	NolinkingModel.write(nolinkingCVECWELog,"TURTLE");
			        //	nolinkingCVECWELog.write(nolinking_cve_cwe);
			        }
			        finally {
			            //linkingModel.close();
			        }
			        
			        //CWEModel.close();
			        
			        
			        
			        return linkingModel;
				
		
	}
	
	
	
public static  ArrayList<String>[] getCPEResourceFilterStatement(String filterStatement, Model CPEModel) throws UnsupportedEncodingException {
		
		
		//query to get cveId property from snort rule
	   	String sidQuery = "select ?cpeId ?s where {\r\n" + 
	   			"    ?s a <http://w3id.org/sepses/vocab/ref/cpe#CPE>.\r\n" + 
	   			"    ?s <http://w3id.org/sepses/vocab/ref/cpe#cpeId> ?cpeId .\r\n" + 
	   			"    filter ("+filterStatement+")\r\n" + 
	   			"} \r\n";
	   	
	   	//System.out.println(sidQuery);System.exit(0);
	   	
		Query sidQ = QueryFactory.create(sidQuery);
		QueryExecution sidQex = QueryExecutionFactory.create(sidQ, CPEModel);
		ResultSet sidQResult = sidQex.execSelect();
		
		//System.exit(0);
		 ArrayList<String> CPEResArray = new ArrayList<String>();
		 ArrayList<String> CPEIdArray = new ArrayList<String>();
		 ArrayList<String>[] CPEArrayOfList = new ArrayList[2];
	
		 while (sidQResult.hasNext()) {
			 QuerySolution sidQS = sidQResult.nextSolution();
			 RDFNode CPERes = sidQS.get("s");
			 RDFNode CPEId = sidQS.get("cpeId");
			 CPEIdArray.add(CPEId.toString());
			 CPEResArray.add(CPERes.toString());
			//System.out.println(CPERes.toString());				 
		 }
		 //System.out.println(CVEResArray);
		 CPEArrayOfList[0]=CPEResArray;
		 CPEArrayOfList[1]=CPEIdArray;
		 
		 //CAPECModel.close();
		// System.exit(0);
		
		 return CPEArrayOfList;
		
		
	  
	}


public static  ArrayList<String>[] getCWEResourceFilterStatement(String filterStatement, Model CWEModel) {
	
	
	//query to get cveId property from snort rule
   	String sidQuery = "select ?cweId ?s where {\r\n" + 
   			"    ?s a <http://w3id.org/sepses/vocab/ref/cwe#CWE>.\r\n" + 
   			"    ?s <http://w3id.org/sepses/vocab/ref/cwe#cweId> ?cweId .\r\n" + 
   			"    filter ("+filterStatement+")\r\n" + 
   			"} \r\n";
   	
//   	System.out.println(sidQuery);System.exit(0);
   	
	Query sidQ = QueryFactory.create(sidQuery);
	QueryExecution sidQex = QueryExecutionFactory.create(sidQ, CWEModel);
	ResultSet sidQResult = sidQex.execSelect();
	
	//System.exit(0);
	 ArrayList<String> CWEResArray = new ArrayList<String>();
	 ArrayList<String> CWEIdArray = new ArrayList<String>();
	 ArrayList<String>[] CWEArrayOfList = new ArrayList[2];
	 	
	 while (sidQResult.hasNext()) {
		 QuerySolution sidQS = sidQResult.nextSolution();
		 RDFNode CWERes = sidQS.get("s");
		 RDFNode CWEId = sidQS.get("cweId");
		 CWEResArray.add(CWERes.toString());
		 CWEIdArray.add(CWEId.toString());
		 
		//System.out.println(CPERes.toString());				 
	 }
	 //System.out.println(CVEResArray);
	 CWEArrayOfList[0]=CWEResArray;
	 CWEArrayOfList[1]=CWEIdArray;
	  
	 //CAPECModel.close();
	// System.exit(0);
	 return CWEArrayOfList;
	
	
  
}
	
		
	//store additional generated linking triple to rdf snort alert
	
	

}
