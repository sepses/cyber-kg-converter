package ac.at.tuwien.ifs.sepses.parser.tool;

import java.util.ArrayList;

import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.query.Query;
import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QueryFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.update.UpdateAction;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import ac.at.tuwien.ifs.sepses.vocab.CAT;

public class CATTool {
	private static final Logger log = LoggerFactory.getLogger(CATTool.class);
	
	public static void updateCATLinks(Model catModel) {
        log.info("updating correct CAT links");
        
        String attackpattern="http://w3id.org/sepses/vocab/ref/attack#attack-pattern";
		String mitretactic="http://w3id.org/sepses/vocab/ref/attack#x-mitre-tactic";
		String courseofaction="http://w3id.org/sepses/vocab/ref/attack#course-of-action";
		String tool="http://w3id.org/sepses/vocab/ref/attack#tool";
		String malware="http://w3id.org/sepses/vocab/ref/attack#malware";
		String intrusionset="http://w3id.org/sepses/vocab/ref/attack#intrusion-set";
		String asset="http://w3id.org/sepses/vocab/ref/attack#x-mitre-asset";
		String campaign="http://w3id.org/sepses/vocab/ref/attack#campaign";
		String datacomponent="http://w3id.org/sepses/vocab/ref/attack#x-mitre-data-component";
		String datasource="http://w3id.org/sepses/vocab/ref/attack#x-mitre-data-source";
		
		//update type conform with the vocabulary
		log.info("updating Type");
		updateType(catModel, attackpattern, CAT.TECHNIQUE);
		updateType(catModel, mitretactic, CAT.TACTIC);
		updateType(catModel, courseofaction, CAT.MITIGATION);
		updateType(catModel, tool, CAT.SOFTWARE);
		updateType(catModel, malware, CAT.MALWARE);
		updateType(catModel, intrusionset, CAT.GROUP);
		updateType(catModel, asset, CAT.ASSET);
		updateType(catModel, campaign, CAT.CAMPAIGN);
		updateType(catModel, datacomponent, CAT.DATA_COMPONENT);
		updateType(catModel, datasource, CAT.DATASOURCE);
		
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
	                 "INSERT  {?st <http://w3id.org/sepses/vocab/ref/attack#isSubTechniqueOf> ?t."+
	             		"}  " + 
	             		"  WHERE { " + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasSourceRef> ?st." + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasTargetRef> ?t." + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#relationshipType> 'subtechnique-of'." + 
	             		"  } ");
			
			
				UpdateRequest updateRequest = UpdateFactory.create(update.toString());
	        UpdateAction.execute(updateRequest, catModel);
	        
	        
			
			//1. mitigates linking (source: mitigation, target :technique => prop: preventsTechnique)
			log.info("1. mitigates linking");
			ParameterizedSparqlString update1 =
	                new ParameterizedSparqlString(
	                 "INSERT  {  ?ca <http://w3id.org/sepses/vocab/ref/attack#preventsTechnique> ?ap."
	                 + "?ap <http://w3id.org/sepses/vocab/ref/attack#hasMitigation> ?ca"+
	             		"}  " + 
	             		"  WHERE { " + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasSourceRef> ?ca." + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasTargetRef> ?ap." + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#relationshipType> 'mitigates'." + 
	             		"  } ");
			
			
				UpdateRequest updateRequest1 = UpdateFactory.create(update1.toString());
	        UpdateAction.execute(updateRequest1, catModel);
	        
	              
            //2. uses linking (source: Group, target: technique => prop : usesTechnique	)
	        log.info("2. uses linking 1");
	        ParameterizedSparqlString update2 =
	                new ParameterizedSparqlString(
	                 "INSERT  {  ?sr <http://w3id.org/sepses/vocab/ref/attack#usesTechnique> ?tr."+
	                		       		"}  " + 
	             		"  WHERE { " + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasSourceRef> ?sr." + 
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasTargetRef> ?tr." +
	             		"    ?sr a <http://w3id.org/sepses/vocab/ref/attack#Group>." +
	             		"    ?tr a <http://w3id.org/sepses/vocab/ref/attack#Technique>." +
	             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#relationshipType> 'uses'." + 
	             		"  } ");
			
			
			  UpdateRequest updateRequest2 = UpdateFactory.create(update2.toString());
	           UpdateAction.execute(updateRequest2, catModel);
	        
	        
	        
	        //3. uses linking (source: Software, target: technique => prop : implementsTechnique)
	           log.info("3. uses linking 2");
	           ParameterizedSparqlString update3 =
		                new ParameterizedSparqlString(
		                 "INSERT  {  ?sr <http://w3id.org/sepses/vocab/ref/attack#implementsTechnique> ?tr."+
		                		  "?tr <http://w3id.org/sepses/vocab/ref/attack#hasMalware> ?sr"+
		                		 "}  " + 
		             		"  WHERE { " + 
		             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasSourceRef> ?sr." + 
		             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasTargetRef> ?tr." +
		             		"    ?sr a <http://w3id.org/sepses/vocab/ref/attack#Malware>." +
		             		"    ?tr a <http://w3id.org/sepses/vocab/ref/attack#Technique>." +
		             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#relationshipType> 'uses'." + 
		             		"  } ");
				
				
				  UpdateRequest updateRequest3 = UpdateFactory.create(update3.toString());
		           UpdateAction.execute(updateRequest3, catModel);
		        
		           
	           //4. uses linking (source: Group, target: Software => prop: usesSoftware )
		           log.info("4. uses linking 3");
		           ParameterizedSparqlString update4 =
			                new ParameterizedSparqlString(
			                 "INSERT  {  ?sr <http://w3id.org/sepses/vocab/ref/attack#usesMalware> ?tr."
			                           + "?tr <http://w3id.org/sepses/vocab/ref/attack#hasGroup> ?sr"+
			             		"}  " + 
			             		"  WHERE { " + 
			             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasSourceRef> ?sr." + 
			             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasTargetRef> ?tr." +
			             		"    ?sr a <http://w3id.org/sepses/vocab/ref/attack#Group>." +
			             		"    ?tr a <http://w3id.org/sepses/vocab/ref/attack#Malware>." +
			             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#relationshipType> 'uses'." + 
			             		"  } ");
					
					
					  UpdateRequest updateRequest4 = UpdateFactory.create(update4.toString());
			           UpdateAction.execute(updateRequest4, catModel);
			           
			           
			           //4.1 target asset linking (source: Technique, target: Asset => prop: targetAsset )
				           log.info("4.1 target asset linking");
				           ParameterizedSparqlString update41 =
					                new ParameterizedSparqlString(
					                 "INSERT  {  ?sr <http://w3id.org/sepses/vocab/ref/attack#targetsAsset> ?tr."
					                           + "?tr <http://w3id.org/sepses/vocab/ref/attack#hasTechnique> ?sr"+
					             		"}  " + 
					             		"  WHERE { " + 
					             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasSourceRef> ?sr." + 
					             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasTargetRef> ?tr." +
					             		"    ?sr a <http://w3id.org/sepses/vocab/ref/attack#Technique>." +
					             		"    ?tr a <http://w3id.org/sepses/vocab/ref/attack#Asset>." +
					             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#relationshipType> 'targets'." + 
					             		"  } ");
							
							
							  UpdateRequest updateRequest41 = UpdateFactory.create(update41.toString());
					           UpdateAction.execute(updateRequest41, catModel);
					           
					         //4.2 uses technique linking (source: Campaign, uses: Technique => prop: usesTechnique )
					           log.info("4.2 uses technique linking");
					           ParameterizedSparqlString update42 =
						                new ParameterizedSparqlString(
						                 "INSERT  {  ?sr <http://w3id.org/sepses/vocab/ref/attack#usesTechnique> ?tr."
						                           + "?tr <http://w3id.org/sepses/vocab/ref/attack#hasCampaign> ?sr"+
						             		"}  " + 
						             		"  WHERE { " + 
						             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasSourceRef> ?sr." + 
						             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasTargetRef> ?tr." +
						             		"    ?sr a <http://w3id.org/sepses/vocab/ref/attack#Campaign>." +
						             		"    ?tr a <http://w3id.org/sepses/vocab/ref/attack#Technique>." +
						             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#relationshipType> 'uses'." + 
						             		"  } ");
								
								
								  UpdateRequest updateRequest42 = UpdateFactory.create(update42.toString());
						           UpdateAction.execute(updateRequest42, catModel);
			        
						           //4.3 detects technique linking (source: Data Component, detects: Technique => prop: detectsTechnique )
						           log.info("4.2 uses technique linking");
						           ParameterizedSparqlString update43 =
							                new ParameterizedSparqlString(
							                 "INSERT  {  ?sr <http://w3id.org/sepses/vocab/ref/attack#detectsTechnique> ?tr."
							                           + "?tr <http://w3id.org/sepses/vocab/ref/attack#usesDataComponent> ?sr"+
							             		"}  " + 
							             		"  WHERE { " + 
							             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasSourceRef> ?sr." + 
							             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#hasTargetRef> ?tr." +
							             		"    ?sr a <http://w3id.org/sepses/vocab/ref/attack#DataComponent>." +
							             		"    ?tr a <http://w3id.org/sepses/vocab/ref/attack#Technique>." +
							             		"    ?rel <http://w3id.org/sepses/vocab/ref/attack#relationshipType> 'detects'." + 
							             		"  } ");
									
									
									  UpdateRequest updateRequest43 = UpdateFactory.create(update43.toString());
							           UpdateAction.execute(updateRequest43, catModel);
							           
			         //5. has Technique linking (source: Technique, target: Tactic => prop: accomplishesTactic )           
			           log.info("5. has Technique linking ");
			           ParameterizedSparqlString update5 =
				                new ParameterizedSparqlString(
				                 "INSERT  {  ?sr <http://w3id.org/sepses/vocab/ref/attack#hasTechnique> ?tr."+
				                     
				             		"}  " + 
				             		"  WHERE { " + 
				             		"    ?tr <http://w3id.org/sepses/vocab/ref/attack#accomplishesTactic> ?sr ." +
				             		"  } ");
						
						
						  UpdateRequest updateRequest5 = UpdateFactory.create(update5.toString());
				           UpdateAction.execute(updateRequest5, catModel);
				        
				           
				           
				         //6. update tactic resource pattern        
				           log.info("6. update tactic resource pattern");
				           
				           String query= "select ?a ?sn where {?a a <http://w3id.org/sepses/vocab/ref/attack#Tactic>; <http://w3id.org/sepses/vocab/ref/attack#shortname> ?sn.}";
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
				                Resource snr = catModel.createResource("http://w3id.org/sepses/resource/attack/tactic/"+sn);
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
					                 "INSERT  {  ?s <http://w3id.org/sepses/vocab/ref/attack#hasCAPEC> ?cp."+
					             		"}  " + 
					             		"  WHERE { " + 
					             		"    ?s <http://w3id.org/sepses/vocab/ref/attack#hasReference> ?ref." + 
					             		"    ?ref <http://w3id.org/sepses/vocab/ref/attack#referenceName> 'capec'." +
					             		"    ?ref <http://w3id.org/sepses/vocab/ref/attack#referenceId> ?refId."
					             		+ " BIND (IRI(CONCAT('http://w3id.org/sepses/resource/capec/',?refId,'')) AS ?cp)" +
					             		 		"  } ");
							
							
							  UpdateRequest updateRequest7 = UpdateFactory.create(update7.toString());
					           UpdateAction.execute(updateRequest7, catModel);
				           //8.0 Remove relationship connection
				           log.info("8. remove relationship");
				           
				           ParameterizedSparqlString update8 = new ParameterizedSparqlString(
					                 "DELETE  { ?s ?p ?o}"+
					             		"  WHERE { " + 
					             		"  ?s <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://w3id.org/sepses/vocab/ref/attack#relationship>;"
					             		+ "?p ?o" + 
					             		"  } ");
							
							
								UpdateRequest updateRequest8 = UpdateFactory.create(update8.toString());
					        UpdateAction.execute(updateRequest8, catModel);
					      

					        //9.0 change technique resource id   
					       
					        log.info("9. change technique resource id ");
					        
					        ParameterizedSparqlString update9 =
					                new ParameterizedSparqlString(
					                		"DELETE  {  ?a ?b ?s. ?s ?p ?o.}"+
					                		"INSERT  {  ?a ?b ?tech. ?tech ?p ?o."
					                		+ "?tech <http://w3id.org/sepses/vocab/ref/attack#hasMitreAttack> ?s"+
					             		"}  " + 
					             		"  WHERE { " + 
					             		"    ?s a <http://w3id.org/sepses/vocab/ref/attack#Technique>." +
					             		"    ?s ?p ?o." +
					             		"    ?a ?b ?s." +
					             		"    ?s <http://purl.org/dc/terms/title> ?t." 
					             		+ " BIND (IRI(CONCAT('http://w3id.org/sepses/resource/attack/technique/',LCASE(REPLACE(REPLACE(STR(?t),' ','-'),'/','-')))) AS ?tech)" +
					             		 		"  } ");
							
							
							  UpdateRequest updateRequest9 = UpdateFactory.create(update9.toString());
					           UpdateAction.execute(updateRequest9, catModel);
					           
					           //9.b change sub-technique id   
						       
						        log.info("9.b change sub-technique ");
						        
						        ParameterizedSparqlString update9b =
						                new ParameterizedSparqlString(
						                		"DELETE  {  ?ap <http://w3id.org/sepses/vocab/ref/attack#isSubTechniqueOf> ?s.}"+
						                		"INSERT  { "
						                		+ "?s2 <http://w3id.org/sepses/vocab/ref/attack#isSubTechniqueOf> ?s"+
						             		"}  " + 
						             		"  WHERE { " + 
						             		"    ?ap <http://w3id.org/sepses/vocab/ref/attack#isSubTechniqueOf> ?s." +
						             		"    ?s2 <http://w3id.org/sepses/vocab/ref/attack#hasMitreAttack> ?ap." +
						             		"  } ");
								
								
								  UpdateRequest updateRequest9b = UpdateFactory.create(update9b.toString());
						           UpdateAction.execute(updateRequest9b, catModel);
						           
						         //9.b  remove hasMitreAttack  
							       
							        log.info("9.c remove hasMitreAttack ");
							        
							        ParameterizedSparqlString update9c =
							                new ParameterizedSparqlString(
							                		"DELETE  {  ?s ?p ?ap.}"+
			
							             		"  WHERE { " + 
							             		"    ?s ?p ?ap." +
							             		"    ?s2 <http://w3id.org/sepses/vocab/ref/attack#hasMitreAttack> ?ap." +
							             		"  } ");
									
									
									  UpdateRequest updateRequest9c = UpdateFactory.create(update9c.toString());
							           UpdateAction.execute(updateRequest9c, catModel);

//	
							           
									      //11 change asset resource id   
								       
//								        log.info("11. change asset resource id ");
//								        
								        ParameterizedSparqlString update11 =
								                new ParameterizedSparqlString(
								                		"DELETE  {  ?a ?b ?s. ?s ?p ?o.}"+
								                		"INSERT  {  ?a ?b ?asset. ?asset ?p ?o. "+
								             		"}  " + 
								             		"  WHERE { " + 
								             		"    ?s a <http://w3id.org/sepses/vocab/ref/attack#Asset>." +
								             		"    ?s ?p ?o." +
								             		"    OPTIONAL {?a ?b ?s}." +
								             		"    ?s <http://purl.org/dc/terms/title> ?t." 
								             		+ " BIND (IRI(CONCAT('http://w3id.org/sepses/resource/attack/asset/',LCASE(REPLACE(REPLACE(STR(?t),' ','-'),'/','-')),'')) AS ?asset)" +
								             		 		"  } ");
										
										
										 UpdateRequest updateRequest11 = UpdateFactory.create(update11.toString());
								         UpdateAction.execute(updateRequest11, catModel);
								       
									        log.info("12. change malware resource id ");
									        
									        ParameterizedSparqlString update12 =
									                new ParameterizedSparqlString(
									                		"DELETE  {  ?a ?b ?s. ?s ?p ?o.}"+
									                		"INSERT  {  ?a ?b ?ss. ?ss ?p ?o. "+
									             		"}  " + 
									             		"  WHERE { " + 
									             		"    ?s a <http://w3id.org/sepses/vocab/ref/attack#Malware>." +
									             		"    ?s ?p ?o." +
									             		"    OPTIONAL {?a ?b ?s}." +
									             		"    ?s <http://purl.org/dc/terms/title> ?t." 
									             		+ " BIND (IRI(CONCAT('http://w3id.org/sepses/resource/attack/malware/',LCASE(REPLACE(REPLACE(STR(?t),' ','-'),'/','-')),'')) AS ?ss)" +
									
									                		"  } ");
											
											
											 UpdateRequest updateRequest12 = UpdateFactory.create(update12.toString());
									         UpdateAction.execute(updateRequest12, catModel);    
									         
									         log.info("13. change mitigation resource id ");
										        
										        ParameterizedSparqlString update13 =
										                new ParameterizedSparqlString(
										                		"DELETE  {  ?a ?b ?s. ?s ?p ?o.}"+
										                		"INSERT  {  ?a ?b ?ss. ?ss ?p ?o. "+
										             		"}  " + 
										             		"  WHERE { " + 
										             		"    ?s a <http://w3id.org/sepses/vocab/ref/attack#Mitigation>." +
										             		"    ?s ?p ?o." +
										             		"    OPTIONAL {?a ?b ?s}." +
										             		"    ?s <http://purl.org/dc/terms/title> ?t." 
										             		+ " BIND (IRI(CONCAT('http://w3id.org/sepses/resource/attack/mitigation/',LCASE(REPLACE(REPLACE(STR(?t),' ','-'),'/','-')),'')) AS ?ss)" +
										                		"  } ");
												
												
												 UpdateRequest updateRequest13 = UpdateFactory.create(update13.toString());
										         UpdateAction.execute(updateRequest13, catModel);   
					        
										         log.info("14. change group resource id ");
											        
											        ParameterizedSparqlString update14 =
											                new ParameterizedSparqlString(
											                		"DELETE  {  ?a ?b ?s. ?s ?p ?o.}"+
											                		"INSERT  {  ?a ?b ?ss. ?ss ?p ?o. "+
											             		"}  " + 
											             		"  WHERE { " + 
											             		"    ?s a <http://w3id.org/sepses/vocab/ref/attack#Group>." +
											             		"    ?s ?p ?o." +
											             		"    OPTIONAL {?a ?b ?s}." +
											             		"    ?s <http://purl.org/dc/terms/title> ?t." 
											             		+ " BIND (IRI(CONCAT('http://w3id.org/sepses/resource/attack/group/',LCASE(REPLACE(REPLACE(STR(?t),' ','-'),'/','-')),'')) AS ?ss)" +
											                		"  } ");
													
													
													 UpdateRequest updateRequest14 = UpdateFactory.create(update14.toString());
											         UpdateAction.execute(updateRequest14, catModel); 
					        
											         log.info("15. change Campaign resource id ");
												        
												        ParameterizedSparqlString update15 =
												                new ParameterizedSparqlString(
												                		"DELETE  {  ?a ?b ?s. ?s ?p ?o.}"+
												                		"INSERT  {  ?a ?b ?ss. ?ss ?p ?o. "+
												             		"}  " + 
												             		"  WHERE { " + 
												             		"    ?s a <http://w3id.org/sepses/vocab/ref/attack#Campaign>." +
												             		"    ?s ?p ?o." +
												             		"    OPTIONAL {?a ?b ?s}." +
												             		"    ?s <http://purl.org/dc/terms/title> ?t." 
												             		+ " BIND (IRI(CONCAT('http://w3id.org/sepses/resource/attack/campaign/',LCASE(REPLACE(REPLACE(STR(?t),' ','-'),'/','-')),'')) AS ?ss)" +
												                		"  } ");
														
														
														 UpdateRequest updateRequest15 = UpdateFactory.create(update15.toString());
												         UpdateAction.execute(updateRequest15, catModel); 
												         
												         log.info("16. change data source resource id ");
													        
													        ParameterizedSparqlString update16 =
													                new ParameterizedSparqlString(
													                		"DELETE  {  ?a ?b ?s. ?s ?p ?o.}"+
													                		"INSERT  {  ?a ?b ?ss. ?ss ?p ?o. "+
													             		"}  " + 
													             		"  WHERE { " + 
													             		"    ?s a <http://w3id.org/sepses/vocab/ref/attack#DataSource>." +
													             		"    ?s ?p ?o." +
													             		"    OPTIONAL {?a ?b ?s}." +
													             		"    ?s <http://purl.org/dc/terms/title> ?t." 
													             		+ " BIND (IRI(CONCAT('http://w3id.org/sepses/resource/attack/datasource/',LCASE(REPLACE(REPLACE(STR(?t),' ','-'),'/','-')),'')) AS ?ss)" +
													                	"  } ");
															
															
															 UpdateRequest updateRequest16 = UpdateFactory.create(update16.toString());
													         UpdateAction.execute(updateRequest16, catModel); 
											         //20.0 clean reference connection 1
					        
					           log.info("20. clean reference connection 1 ");
					           ParameterizedSparqlString update20 = new ParameterizedSparqlString(
					                 "DELETE  { ?s ?p ?o.}"+
					             		"  WHERE { " + 
					             		"  ?s <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://w3id.org/sepses/vocab/ref/attack#Reference>."
					             		+ "?s ?p ?o."+
					             		"  } ");
							
							
								UpdateRequest updateRequest20 = UpdateFactory.create(update20.toString());
					        UpdateAction.execute(updateRequest20, catModel);
					        
					      //21 clean reference connection 2
					        
					        log.info("21. clean reference connection 2 ");
					        ParameterizedSparqlString update21 = new ParameterizedSparqlString(
					                 "DELETE  { ?s <http://w3id.org/sepses/vocab/ref/attack#hasReference> ?o.}"+
					             		"  WHERE { "  
					             		+ "?s ?p ?o."+
					             		"  } ");
								UpdateRequest updateRequest21 = UpdateFactory.create(update21.toString());
					        UpdateAction.execute(updateRequest21, catModel);
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
