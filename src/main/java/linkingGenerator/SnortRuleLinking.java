package linkingGenerator;

import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;

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

public class SnortRuleLinking {
	
	
	public static void main(String[] args) throws IOException {
		
		//load and read the rdf snort Rule
	
		Model snortRuleModel = ModelFactory.createDefaultModel() ;
		snortRuleModel.read("output/snort/snort_rule3_notype.ttl") ;
		
			
		//find the linking, if it exists generate linking otherwise make a log

			//query to get cveId property from snort alert
		   	String sidQuery = 
		   			"select distinct ?cveId where {\r\n" + 
		   			"    ?s a <http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#SnortRule>.\r\n" + 
		   			"   ?s <http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#hasRuleOption> ?ro.\r\n" + 
		   			"    ?ro <http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#hasReference> ?ref.\r\n" + 
		   			"    ?ref <http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#hasCVEId> ?cveId.\r\n" + 
		   			"}\r\n" + 
		   			"";
		   	
			String sidQuery2 = "select ?s ?cveId where {\r\n" + 
					"    ?s a <http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#SnortRule>.\r\n" + 
					"   ?s <http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#hasRuleOption> ?ro.\r\n" + 
					"    ?ro <http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#hasReference> ?ref.\r\n" + 
					"    ?ref <http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#hasCVEId> ?cveId.\r\n" + 
					"}\r\n" + 
					"";
			
			
		   	//generate filter for CVE query
			Query sidQ = QueryFactory.create(sidQuery);
			QueryExecution sidQex = QueryExecutionFactory.create(sidQ, snortRuleModel);
			 ResultSet sidQResult = sidQex.execSelect();
			 String filterStatement = "";
			 while (sidQResult.hasNext()) {
				 QuerySolution sidQS = sidQResult.nextSolution();
				// RDFNode snortRuleRes = sidQS.get("s");
				 RDFNode snortRuleCVE = sidQS.get("cveId");
				 filterStatement = filterStatement+"?cveId = \"CVE-"+snortRuleCVE+"\" || ";
				  
			 }
			 	ArrayList<String> CVEResArray = getCVEResourceFilterStatement(filterStatement+"?cveId = \"0\"");
			 	//System.out.println(CVEResArray);System.exit(0);
			 	 
			 	Query sidQ2 = QueryFactory.create(sidQuery2);
				QueryExecution sidQex2 = QueryExecutionFactory.create(sidQ2, snortRuleModel);
			 	ResultSet sidQResult2 = sidQex2.execSelect();
			 	
			 	//make new model for lingking result 
			 	Model linkingModel = ModelFactory.createDefaultModel();
			    Property hasCVE = linkingModel.createProperty("http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#hasCVE"); 
			    String nolinking = ""; 
				 while (sidQResult2.hasNext()) {
					 QuerySolution sidQS2 = sidQResult2.nextSolution();
					 RDFNode snortRuleRes2 = sidQS2.get("s");
					 RDFNode snortRuleCVE2 = sidQS2.get("cveId");
					 
				    
					 
					 
					 String lista = "http://example.org/sepses/cve#CVE-"+snortRuleCVE2.toString();
					// System.out.println(lista);
					 
							 
					  if (CVEResArray.contains(lista)) {
						  Resource resS = linkingModel.createResource(snortRuleRes2.toString());
						  Resource resO = linkingModel.createResource(lista);
						  resS.addProperty(hasCVE,resO);
						   // System.out.println(snortRuleRes2.toString()+" "+lista);
						} else {
							   nolinking=snortRuleRes2.toString()+",cveId:"+snortRuleCVE2.toString()+"\n"+nolinking;
							//System.out.println(snortRuleCVE2.toString()+" has no linking !! ");  
						}
					  
				 }
				 
				 linkingModel.write(System.out,"TURTLE"); 
				 
				 String fileName = "output/linking/snortRuleToCVE.ttl";
				 String fileNameNL = "output/linking/snortRuleToCVE_NoLinking.log";
			        FileWriter rdfLingking = new FileWriter(fileName);
			        FileWriter nolinkingLog = new FileWriter(fileNameNL);
			        try {
			        	linkingModel.write(rdfLingking,"N3");
			        	nolinkingLog.write(nolinking);
			        }
			        finally {
			           linkingModel.close();
			        }
			        
			        snortRuleModel.close();
				
		
	}
	

public static  ArrayList<String> getCVEResourceFilterStatement(String filterStatement) {
		
		Model CVEModel = ModelFactory.createDefaultModel() ;
		CVEModel.read("output/cveallyear.ttl") ;
		
		//query to get cveId property from snort rule
	   	String sidQuery = "select ?cveId ?s where {\r\n" + 
	   			"    ?s a <http://sepses.ifs.tuwien.ac.at/vocab/ref/cve#CVE>.\r\n" + 
	   			"    ?s <http://sepses.ifs.tuwien.ac.at/vocab/ref/cve#CVEId> ?cveId .\r\n" + 
	   			"    filter ("+filterStatement+")\r\n" + 
	   			"} \r\n";
	   	
	   	//System.out.println(sidQuery);System.exit(0);
	   	
		Query sidQ = QueryFactory.create(sidQuery);
		QueryExecution sidQex = QueryExecutionFactory.create(sidQ, CVEModel);
		ResultSet sidQResult = sidQex.execSelect();
		
		//System.exit(0);
		 ArrayList<String> CVEResArray = new ArrayList<String>();
	
		 while (sidQResult.hasNext()) {
			 QuerySolution sidQS = sidQResult.nextSolution();
			 RDFNode CVERes = sidQS.get("s");
			 //RDFNode CVEId = sidQS.get("cveId");
			 CVEResArray.add(CVERes.toString());
			//System.out.println(CVERes.toString());				 
		 }
		 //System.out.println(CVEResArray);
		 
		 CVEModel.close();
		// System.exit(0);
		 return CVEResArray;
		
		
	  
	}
		
	//store additional generated linking triple to rdf snort alert
	
	

}
