package ac.at.tuwien.ifs.sepses.parser.tool;

import java.util.ArrayList;

import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.query.Query;
import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QueryFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.Literal;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.ResourceFactory;
import org.apache.jena.rdf.model.Statement;
import org.apache.jena.update.UpdateAction;
import org.apache.jena.update.UpdateExecutionFactory;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateProcessor;
import org.apache.jena.update.UpdateRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import ac.at.tuwien.ifs.sepses.vocab.CAT;

public class CATTool {
	private static final Logger log = LoggerFactory.getLogger(CATTool.class);
	
	public static void updateCATLinks(Model catModel) {
        log.info("updating correct CAT links");
        
        String attackpattern="http://w3id.org/sepses/vocab/ref/cat#attack-pattern";
		String mitretactic="http://w3id.org/sepses/vocab/ref/cat#x-mitre-tactic";
		String courseofaction="http://w3id.org/sepses/vocab/ref/cat#course-of-action";
		String tool="http://w3id.org/sepses/vocab/ref/cat#tool";
		String malware="http://w3id.org/sepses/vocab/ref/cat#malware";
		String relationship="http://w3id.org/sepses/vocab/ref/cat#relationship";
		String intrusionset="http://w3id.org/sepses/vocab/ref/cat#intrusion-set";
		
		//update type conform with the vocabulary
		log.info("updating Type");
		updateType(catModel, attackpattern, CAT.TECHNIQUE);
		updateType(catModel, mitretactic, CAT.TACTIC);
		updateType(catModel, courseofaction, CAT.MITIGATION);
		updateType(catModel, tool, CAT.SOFTWARE);
		updateType(catModel, malware, CAT.SOFTWARE);
		updateType(catModel, intrusionset, CAT.GROUP);
		
		log.info("updating relationship");
		parseRelationship(catModel);
		
     // catModel.write(System.out,"TURTLE");
     // System.exit(0);
        
        	           
             log.info("updating correct CAT links ... done");
    }

		public static void updateType(Model catModel, String t, Resource r) {
		
		
		Resource oldtype = catModel.createResource(t);
		Property type = catModel.createProperty("http://www.w3.org/1999/02/22-rdf-syntax-ns#type");
        ParameterizedSparqlString update =
                new ParameterizedSparqlString("DELETE { ?a ?p1 ?b } INSERT { ?a ?p1 ?b1 }  WHERE { ?a ?p1 ?b } ");
        update.setParam("b", oldtype);
        update.setParam("p1", type);
        update.setParam("b1", r);
        //System.out.println(update.toString());
        //System.exit(0);
        UpdateRequest updateRequest = UpdateFactory.create(update.toString());
        UpdateAction.execute(updateRequest, catModel);
        //System.out.println("test");

	}
		public static void parseRelationship(Model catModel) {
			
			//0. subtechnique linking (source: subtechnique, target :technique => prop: subTechniqueOf)
			log.info("0. subtechnique linking");
			ParameterizedSparqlString update =
	                new ParameterizedSparqlString(
	                 "INSERT  {?st <http://w3id.org/sepses/vocab/ref/cat#isSubTechniqueOf> ?t."+
	             		"}  " + 
	             		"  WHERE { " + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#hasSourceRef> ?st." + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#hasTargetRef> ?t." + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#relationshipType> 'subtechnique-of'." + 
	             		"  } ");
			
			
				UpdateRequest updateRequest = UpdateFactory.create(update.toString());
	        UpdateAction.execute(updateRequest, catModel);
	        
	        
			
			//1. mitigates linking (source: mitigation, target :technique => prop: preventsTechnique)
			log.info("1. mitigates linking");
			ParameterizedSparqlString update1 =
	                new ParameterizedSparqlString(
	                 "INSERT  {  ?ca <http://w3id.org/sepses/vocab/ref/cat#preventsTechnique> ?ap."
	                 + "?ap <http://w3id.org/sepses/vocab/ref/cat#hasMitigation> ?ca"+
	             		"}  " + 
	             		"  WHERE { " + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#hasSourceRef> ?ca." + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#hasTargetRef> ?ap." + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#relationshipType> 'mitigates'." + 
	             		"  } ");
			
			
				UpdateRequest updateRequest1 = UpdateFactory.create(update1.toString());
	        UpdateAction.execute(updateRequest1, catModel);
	        
	              
            //2. uses linking (source: Group, target: technique => prop : usesTechnique	)
	        log.info("2. uses linking 1");
	        ParameterizedSparqlString update2 =
	                new ParameterizedSparqlString(
	                 "INSERT  {  ?sr <http://w3id.org/sepses/vocab/ref/cat#usesTechnique> ?tr."+
	                		       		"}  " + 
	             		"  WHERE { " + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#hasSourceRef> ?sr." + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#hasTargetRef> ?tr." +
	             		"    ?sr a <http://w3id.org/sepses/vocab/ref/cat#Group>." +
	             		"    ?tr a <http://w3id.org/sepses/vocab/ref/cat#Technique>." +
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#relationshipType> 'uses'." + 
	             		"  } ");
			
			
			  UpdateRequest updateRequest2 = UpdateFactory.create(update2.toString());
	           UpdateAction.execute(updateRequest2, catModel);
	        
	        
	        
	        //3. uses linking (source: Software, target: technique => prop : implementsTechnique)
	           log.info("3. uses linking 2");
	           ParameterizedSparqlString update3 =
		                new ParameterizedSparqlString(
		                 "INSERT  {  ?sr <http://w3id.org/sepses/vocab/ref/cat#implementsTechnique> ?tr."+
		                		  "?tr <http://w3id.org/sepses/vocab/ref/cat#hasSoftware> ?sr"+
		                		 "}  " + 
		             		"  WHERE { " + 
		             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#hasSourceRef> ?sr." + 
		             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#hasTargetRef> ?tr." +
		             		"    ?sr a <http://w3id.org/sepses/vocab/ref/cat#Software>." +
		             		"    ?tr a <http://w3id.org/sepses/vocab/ref/cat#Technique>." +
		             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#relationshipType> 'uses'." + 
		             		"  } ");
				
				
				  UpdateRequest updateRequest3 = UpdateFactory.create(update3.toString());
		           UpdateAction.execute(updateRequest3, catModel);
		        
		           
	           //4. uses linking (source: Group, target: Software => prop: usesSoftware )
		           log.info("4. uses linking 3");
		           ParameterizedSparqlString update4 =
			                new ParameterizedSparqlString(
			                 "INSERT  {  ?sr <http://w3id.org/sepses/vocab/ref/cat#usesSoftware> ?tr."
			                           + "?tr <http://w3id.org/sepses/vocab/ref/cat#hasGroup> ?sr"+
			             		"}  " + 
			             		"  WHERE { " + 
			             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#hasSourceRef> ?sr." + 
			             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#hasTargetRef> ?tr." +
			             		"    ?sr a <http://w3id.org/sepses/vocab/ref/cat#Group>." +
			             		"    ?tr a <http://w3id.org/sepses/vocab/ref/cat#Software>." +
			             		"    ?rel <http://w3id.org/sepses/vocab/ref/cat#relationshipType> 'uses'." + 
			             		"  } ");
					
					
					  UpdateRequest updateRequest4 = UpdateFactory.create(update4.toString());
			           UpdateAction.execute(updateRequest4, catModel);
			        
			         //5. has Technique linking (source: Technique, target: Tactic => prop: accomplishesTactic )           
			           log.info("5. has Technique linking ");
			           ParameterizedSparqlString update5 =
				                new ParameterizedSparqlString(
				                 "INSERT  {  ?sr <http://w3id.org/sepses/vocab/ref/cat#hasTechnique> ?tr."+
				                     
				             		"}  " + 
				             		"  WHERE { " + 
				             		"    ?tr <http://w3id.org/sepses/vocab/ref/cat#accomplishesTactic> ?sr ." +
				             		"  } ");
						
						
						  UpdateRequest updateRequest5 = UpdateFactory.create(update5.toString());
				           UpdateAction.execute(updateRequest5, catModel);
				        
				           
				           
				         //6. update tactic resource pattern        
				           log.info("6. update tactic resource pattern");
				           
				           String query= "select ?a ?sn where {?a a <http://w3id.org/sepses/vocab/ref/cat#Tactic>; <http://w3id.org/sepses/vocab/ref/cat#shortname> ?sn.}";
				           //System.out.println(query);
				           Query QVC = QueryFactory.create(query);
				           QueryExecution qeQVC = QueryExecutionFactory.create(QVC,catModel);
				           ResultSet rs = qeQVC.execSelect();
				           ArrayList<Resource> resa =  new ArrayList<Resource>();
				           ArrayList<Resource> resb =  new ArrayList<Resource>();
				           while (rs.hasNext()) {
				          	      QuerySolution qsQuery = rs.nextSolution();
				                 
				                Resource a = qsQuery.getResource("?a");
				                String sn = qsQuery.getLiteral("?sn").toString();
				                Resource snr = catModel.createResource("http://w3id.org/sepses/resource/cat/tactic/"+sn);
				                //System.out.print(a+" | ");
				                //System.out.println(snr);
				                resa.add(a);
				                resb.add(snr);
				                //updateTacticResource(catModel, a, snr);
				           }
				           //System.exit(0);
				           for (int i=0; i<resa.size(); i++) {
//				        	 System.out.print(resa.get(i)+" | ");
//				                System.out.println(resb.get(i));
//				                
				        	   updateTacticResource(catModel, resa.get(i), resb.get(i));
				           }
				           //System.exit(0);
				           
				           //7.0 create CAPEC linking based on reference
				           log.info("7. create CAPEC linking based on reference ");
				           ParameterizedSparqlString update7 =
					                new ParameterizedSparqlString(
					                 "INSERT  {  ?s <http://w3id.org/sepses/vocab/ref/cat#hasCAPEC> ?cp."+
					             		"}  " + 
					             		"  WHERE { " + 
					             		"    ?s <http://w3id.org/sepses/vocab/ref/cat#hasReference> ?ref." + 
					             		"    ?ref <http://w3id.org/sepses/vocab/ref/cat#referenceName> 'capec'." +
					             		"    ?ref <http://w3id.org/sepses/vocab/ref/cat#referenceId> ?refId."
					             		+ " BIND (IRI(CONCAT('http://w3id.org/sepses/resource/capec/',?refId,'')) AS ?cp)" +
					             		 		"  } ");
							
							
							  UpdateRequest updateRequest7 = UpdateFactory.create(update7.toString());
					           UpdateAction.execute(updateRequest7, catModel);
				           //8.0 Remove relationship connection
				           log.info("8. remove relationship");
				           
				           ParameterizedSparqlString update8 = new ParameterizedSparqlString(
					                 "DELETE  { ?s ?p ?o}"+
					             		"  WHERE { " + 
					             		"  ?s <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://w3id.org/sepses/vocab/ref/cat#relationship>;"
					             		+ "?p ?o" + 
					             		"  } ");
							
							
								UpdateRequest updateRequest8 = UpdateFactory.create(update8.toString());
					        UpdateAction.execute(updateRequest8, catModel);
					      

					        //9.0 change technique resource id   
					       
					        log.info("9. change technique resource id ");
					        
					        ParameterizedSparqlString update11 =
					                new ParameterizedSparqlString(
					                		"DELETE  {  ?a ?b ?s. ?s ?p ?o.}"+
					                		"INSERT  {  ?a ?b ?tech. ?tech ?p ?o. "
					                		+ "?tech <http://w3id.org/sepses/vocab/ref/cat#hasMitreAttack> ?s"+
					             		"}  " + 
					             		"  WHERE { " + 
					             		"    ?s a <http://w3id.org/sepses/vocab/ref/cat#Technique>." +
					             		"    ?s ?p ?o." +
					             		"    ?a ?b ?s." +
					             		"    ?s <http://w3id.org/sepses/vocab/ref/cat#hasReference> ?ref." + 
					             		"    ?ref <http://w3id.org/sepses/vocab/ref/cat#referenceName> 'mitre-attack'." +
					             		"    ?ref <http://w3id.org/sepses/vocab/ref/cat#referenceId> ?refId."
					             		+ " BIND (IRI(CONCAT('http://w3id.org/sepses/resource/cat/technique/',?refId,'')) AS ?tech)" +
					             		 		"  } ");
							
							
							  UpdateRequest updateRequest11 = UpdateFactory.create(update11.toString());
					           UpdateAction.execute(updateRequest11, catModel);
					           
					           //9.b change technique resource id   
						       
						        log.info("9.b change technique resource id ");
						        
						        ParameterizedSparqlString update11b =
						                new ParameterizedSparqlString(
						                		"DELETE  {  ?ap <http://w3id.org/sepses/vocab/ref/cat#isSubTechniqueOf> ?s.}"+
						                		"INSERT  { "
						                		+ "?s2 <http://w3id.org/sepses/vocab/ref/cat#isSubTechniqueOf> ?s"+
						             		"}  " + 
						             		"  WHERE { " + 
						             		"    ?ap <http://w3id.org/sepses/vocab/ref/cat#isSubTechniqueOf> ?s." +
						             		"    ?s2 <http://w3id.org/sepses/vocab/ref/cat#hasMitreAttack> ?ap." +
						             		"  } ");
								
								
								  UpdateRequest updateRequest11b = UpdateFactory.create(update11b.toString());
						           UpdateAction.execute(updateRequest11b, catModel);
						           
						         //9.b change technique resource id   
							       
							        log.info("9.c change technique resource id ");
							        
							        ParameterizedSparqlString update11c =
							                new ParameterizedSparqlString(
							                		"DELETE  {  ?s ?p ?ap.}"+
			
							             		"  WHERE { " + 
							             		"    ?s ?p ?ap." +
							             		"    ?s2 <http://w3id.org/sepses/vocab/ref/cat#hasMitreAttack> ?ap." +
							             		"  } ");
									
									
									  UpdateRequest updateRequest11c = UpdateFactory.create(update11c.toString());
							           UpdateAction.execute(updateRequest11c, catModel);

//	
					        
					        //10.0 clean reference connection 1
					        
					           log.info("10. clean reference connection 1 ");
						           
					           ParameterizedSparqlString update9 = new ParameterizedSparqlString(
					                 "DELETE  { ?s ?p ?o.}"+
					             		"  WHERE { " + 
					             		"  ?s <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://w3id.org/sepses/vocab/ref/cat#Reference>."
					             		+ "?s ?p ?o."+
					             		"  } ");
							
							
								UpdateRequest updateRequest9 = UpdateFactory.create(update9.toString());
					        UpdateAction.execute(updateRequest9, catModel);
					        
					      //10.0 clean reference connection 2
					        
					        log.info("11. clean reference connection 2 ");
					        ParameterizedSparqlString update10 = new ParameterizedSparqlString(
					                 "DELETE  { ?s <http://w3id.org/sepses/vocab/ref/cat#hasReference> ?o.}"+
					             		"  WHERE { "  
					             		+ "?s ?p ?o."+
					             		"  } ");
							
							
								UpdateRequest updateRequest10 = UpdateFactory.create(update10.toString());
					        UpdateAction.execute(updateRequest10, catModel);
					      			         
					        
					        
				           
		}
		
	
		
		public static void updateTacticResource(Model catModel, Resource a, Resource snr) {
			ParameterizedSparqlString update =
	                new ParameterizedSparqlString(
	                 "DELETE  {  ?s ?p ?o}"+
	             		" INSERT {?b2 ?p ?o}  " + 
	             		"  WHERE { " + 
	             		"    ?s ?p ?o." +
	             		"  } ");
       
       //System.out.println(snr);
	       update.setParam("s", a);
	       update.setParam("b2", snr);
	       //System.out.println(update.toString());
			  UpdateRequest updateRequest = UpdateFactory.create(update.toString());
	           UpdateAction.execute(updateRequest, catModel);
			}
		
	
}
