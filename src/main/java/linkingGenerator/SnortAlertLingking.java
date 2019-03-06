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

public class SnortAlertLingking {
	
	
	public static void main(String[] args) throws IOException {
		
		//load and read the rdf snort alert
	
		Model snortAlertModel = ModelFactory.createDefaultModel() ;
		snortAlertModel.read("output/snort/snort_alert_new_5000.ttl") ;
		
		//load another rdf that snort alert should link to

	
		
		//find the linking, if it exists generate linking otherwise make a log

			//query to get sid property from snort alert
		   	String sidQuery = "select distinct ?sid where { \r\n" + 
		   		"    ?s a <http://sepses.ifs.tuwien.ac.at/vocab/log/IDSSnortAlertLog#IDSSnortAlertLogEntry>.\r\n" + 
		   		"    ?s <http://sepses.ifs.tuwien.ac.at/vocab/log/IDSSnortAlertLog#signatureId> ?sid.\r\n" + 
		   		"} \r\n";
			String sidQuery2 = "select ?sid ?s where { \r\n" + 
			   		"    ?s a <http://sepses.ifs.tuwien.ac.at/vocab/log/IDSSnortAlertLog#IDSSnortAlertLogEntry>.\r\n" + 
			   		"    ?s <http://sepses.ifs.tuwien.ac.at/vocab/log/IDSSnortAlertLog#signatureId> ?sid.\r\n" + 
			   		"} \r\n";
		   	//check for each result has sid lingking to sid in snort rule
			Query sidQ = QueryFactory.create(sidQuery);
			QueryExecution sidQex = QueryExecutionFactory.create(sidQ, snortAlertModel);
			 ResultSet sidQResult = sidQex.execSelect();
			 String filterStatement = "";
			 while (sidQResult.hasNext()) {
				 QuerySolution sidQS = sidQResult.nextSolution();
				// RDFNode snortAlertRes = sidQS.get("s");
				 RDFNode snortAlertSid = sidQS.get("sid");
				 filterStatement = filterStatement+"?sid = \""+snortAlertSid+"\" || ";
				  
			 }
			 	ArrayList<String> snortRuleResArray = getSnortRuleResourceFilterStatement(filterStatement+"?sid = \"0\"");
			 	//System.out.println(snortRuleResArray);System.exit(0);
			 	 
			 	Query sidQ2 = QueryFactory.create(sidQuery2);
				QueryExecution sidQex2 = QueryExecutionFactory.create(sidQ2, snortAlertModel);
			 	ResultSet sidQResult2 = sidQex2.execSelect();
			 	
			 	//make new model for lingking result 
			 	Model linkingModel = ModelFactory.createDefaultModel();
			    Property hasSnortRule = linkingModel.createProperty("http://sepses.ifs.tuwien.ac.at/vocab/log/IDSSnortAlertLog#hasSnortRule"); 
			    String nolinking = ""; 
				 while (sidQResult2.hasNext()) {
					 QuerySolution sidQS2 = sidQResult2.nextSolution();
					 RDFNode snortAlertRes2 = sidQS2.get("s");
					 RDFNode snortAlertSid2 = sidQS2.get("sid");
					 
				    
					 
					 
					 String lista = "http://example.org/sepses/snortRule#sid-"+snortAlertSid2.toString();
					// System.out.println(lista);
					 
							 
					  if (snortRuleResArray.contains(lista)) {
						  Resource resS = linkingModel.createResource(snortAlertRes2.toString());
						  Resource resO = linkingModel.createResource(lista);
						  resS.addProperty(hasSnortRule,resO);
						   // System.out.println(snortAlertRes2.toString()+" "+lista);
						} else {
							   nolinking=snortAlertRes2.toString()+",SID:"+snortAlertSid2.toString()+"\n"+nolinking;
							//System.out.println(snortAlertRes2.toString()+" has no linking !! ");  
						}
					  
				 }
				 
				 linkingModel.write(System.out,"TURTLE"); 
				 
				 String fileName = "output/linking/snortAlertToRule.ttl";
				 String fileNameNL = "output/linking/snortAlertToRule_NoLinking.log";
			        FileWriter rdfLingking = new FileWriter(fileName);
			        FileWriter nolinkingLog = new FileWriter(fileNameNL);
			        try {
			        	linkingModel.write(rdfLingking,"TURTLE");
			        	nolinkingLog.write(nolinking);
			        }
			        finally {
			           linkingModel.close();
			        }
			        
			        snortAlertModel.close();
				
				 /* if(snortRuleRes != null) {
					System.out.println(snortAlertRes.toString()+" "+snortRuleRes.toString());
				  }else {
					System.out.println(snortAlertRes.toString()+" has no linking !! ");  
					  
				  }*/
				 					 
			 
			
				
			
		
	}
	
	
	
	public static RDFNode getSnortRuleResourceBySid(String sid) {
		
		Model snortRuleModel = ModelFactory.createDefaultModel() ;
		snortRuleModel.read("output/snort/snort_rule3_notype.ttl") ;
		
		//query to get sid property from snort alert
	   	String sidQuery = "select * where { \r\n" + 
	   			"    ?s a <http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#SnortRule> .\r\n" + 
	   			"    ?s <http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#hasRuleOption> ?ro.\r\n" + 
	   			"    ?ro <http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#sid> ?sid .\r\n" + 
	   			"    filter (?sid=\""+sid+"\" )\r\n" + 
	   			"} \r\n";
	   	
	   //	System.out.println(sidQuery);System.exit(0);
	   	
		Query sidQ = QueryFactory.create(sidQuery);
		QueryExecution sidQex = QueryExecutionFactory.create(sidQ, snortRuleModel);
		ResultSet sidQResult = sidQex.execSelect();
		RDFNode snortRuleRes = null;
		 while (sidQResult.hasNext()) {
			 QuerySolution sidQS = sidQResult.nextSolution();
			 snortRuleRes = sidQS.get("s");
			//System.out.println(snortRuleRes.toString());				 
		 }
		 snortRuleModel.close();
		 //System.exit(0);
		 if(snortRuleRes != null) {
			
			 return snortRuleRes;
		 }else {
			 return null;
		 }
		
	  
	}
public static  ArrayList<String> getSnortRuleResourceFilterStatement(String filterStatement) {
		
		Model snortRuleModel = ModelFactory.createDefaultModel() ;
		snortRuleModel.read("output/snort/snort_rule3_notype.ttl") ;
		
		//query to get sid property from snort alert
	   	String sidQuery = "select ?s ?sid where { \r\n" + 
	   			"    ?s a <http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#SnortRule> .\r\n" + 
	   			"    ?s <http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#hasRuleOption> ?ro.\r\n" + 
	   			"    ?ro <http://sepses.ifs.tuwien.ac.at/vocab/rule/snortRule#sid> ?sid .\r\n" + 
	   			"    filter ("+filterStatement+")\r\n" + 
	   			"} \r\n";
	   	
	  // 	System.out.println(sidQuery);System.exit(0);
	   	
		Query sidQ = QueryFactory.create(sidQuery);
		QueryExecution sidQex = QueryExecutionFactory.create(sidQ, snortRuleModel);
		ResultSet sidQResult = sidQex.execSelect();
		//System.out.println(sidQResult.getRowNumber());
		//System.exit(0);
		 ArrayList<String> snortRuleResArray = new ArrayList<String>();
	
		 while (sidQResult.hasNext()) {
			 QuerySolution sidQS = sidQResult.nextSolution();
			 RDFNode snortRuleRes = sidQS.get("s");
			 RDFNode snortRuleSid = sidQS.get("sid");
			// String[] snort = new String[2];
			// snort[0] = snortRuleRes.toString();
			// snort[1]= snortRuleSid.toString();
			// snortRuleResArray.addAll(Arrays.asList(snort));
			 snortRuleResArray.add(snortRuleRes.toString());
			//System.out.println(snortRuleRes.toString());				 
		 }
		 //System.out.println(snortRuleResArray);
		 
		 //snortRuleModel.close();
		// System.exit(0);
		 return snortRuleResArray;
		
		
	  
	}
		
	//store additional generated linking triple to rdf snort alert
	
	

}
