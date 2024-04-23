package ac.at.tuwien.ifs.sepses.parser.tool;

import org.apache.jena.query.Query;
import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QueryFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.DCTerms;
import org.apache.jena.vocabulary.RDF;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ac.at.tuwien.ifs.sepses.vocab.CPE;
import ac.at.tuwien.ifs.sepses.vocab.ICSA;


public class ICSATool {
	private static final Logger log = LoggerFactory.getLogger(ICSATool.class);
		
	public static String[] splitString(String s, String delimiter) {
		String[] sparts = s.split(delimiter);
		return sparts;
	}
	
	
	
	public static ResultSet queryLocalRepository(String queryIn, Model icsaModel){
		  Query query = QueryFactory.create(queryIn);
		  // Execute the query and obtain results
		  QueryExecution qe = QueryExecutionFactory.create(query, icsaModel);
		  ResultSet rs =  qe.execSelect();
		  return rs;
		}
	
	
	public static void createCVEConnection(Model icsaModel) {	
		log.info("create CVE connection");
		
		String q = "prefix icsa: <http://w3id.org/sepses/vocab/ref/icsa#>\r\n"
				+ "select ?s ?cve {\r\n"
				+ "    ?s icsa:cveNumber ?cve\r\n"
				+ "}";
		
		ResultSet rs = queryLocalRepository(q, icsaModel);
	       while (rs.hasNext()) {
	            QuerySolution qsQueryCVE = rs.nextSolution();
	            Resource s = qsQueryCVE.get("?s").asResource();
	            String cve = qsQueryCVE.get("?cve").toString();
	            
	            String[] cves = splitString(cve,",");
	            
	             for (String c:cves) {
	            	 Resource rc = icsaModel.createResource("http://w3id.org/sepses/resource/cve/"+c.replaceAll("\\s+",""));
	            	 icsaModel.add(s, ICSA.HAS_CVE, rc);
	            	// icsaModel.add(rc, DCTerms.title, c.trim());
		            // icsaModel.add(rc, RDF.type, CVE.CVE);
	             }
	        }
	       icsaModel.removeAll(null, ICSA.cveNumber, null);
		}
	
	public static void createCWEConnection(Model icsaModel) {	
		String q = "prefix icsa: <http://w3id.org/sepses/vocab/ref/icsa#>\r\n"
				+ "select ?s ?cwe {\r\n"
				+ "    ?s icsa:cweNumber ?cwe\r\n"
				+ "}";
		
		ResultSet rs = queryLocalRepository(q, icsaModel);
	       while (rs.hasNext()) {
	            QuerySolution qsQueryCWE = rs.nextSolution();
	            Resource s = qsQueryCWE.get("?s").asResource();
	            String cwe = qsQueryCWE.get("?cwe").toString();
	            
	            String[] cwes = splitString(cwe,",");
	            
	             for (String c:cwes) {
	            	 Resource rc = icsaModel.createResource("http://w3id.org/sepses/resource/cwe/"+c.replaceAll("\\s+",""));
	            	 icsaModel.add(s, ICSA.HAS_CWE, rc);
	                // icsaModel.add(rc, DCTerms.title, c.trim());
		            // icsaModel.add(rc, RDF.type, CWE.CWE);
	             }
	        }
	       icsaModel.removeAll(null, ICSA.cweNumber, null);
		}
	
	
	public static void createCriticalInfrastructureConnection(Model icsaModel) {	
		String q = "prefix icsa: <http://w3id.org/sepses/vocab/ref/icsa#>\r\n"
				+ "select ?s ?ci {\r\n"
				+ "    ?s icsa:criticalInfrastructureSector ?ci\r\n"
				+ "}";
		
		ResultSet rs = queryLocalRepository(q, icsaModel);
	       while (rs.hasNext()) {
	            QuerySolution qsQueryCI = rs.nextSolution();
	            Resource s = qsQueryCI.get("?s").asResource();
	            String ci = qsQueryCI.get("?ci").toString();
	            
	            String[] cis = splitString(ci,"[;,:]");

	            
	             for (String c:cis) {
	            	 Resource rc = icsaModel.createResource("http://w3id.org/sepses/resource/criticalInfrastructureSector/"+c.replaceAll("\\s+",""));
	            	 icsaModel.add(s, ICSA.HAS_CRITICAL_INFRASTRUCTURE_SECTOR, rc);
		             icsaModel.add(rc, DCTerms.title, c.trim());
		             icsaModel.add(rc, RDF.type, ICSA.CRITICAL_INFRASTRUCTURE_SECTOR);
	             }
	             
	
	        }
	       icsaModel.removeAll(null, ICSA.criticalInfrastructureSector, null);
		}
	
	public static void createVendorConnection(Model icsaModel) {	
		String q = "prefix icsa: <http://w3id.org/sepses/vocab/ref/icsa#>\r\n"
				+ "select ?s ?v WHERE{\r\n"
				+ "    ?s icsa:vendor ?v;\r\n"
				+ "	\r\n"
				+ "}";
		
		ResultSet rs = queryLocalRepository(q, icsaModel);
	       while (rs.hasNext()) {
	            QuerySolution qsQuery = rs.nextSolution();
	            Resource s = qsQuery.get("?s").asResource();
	            String v = qsQuery.get("?v").toString();
	           
	            
	         	Resource rv = icsaModel.createResource("http://w3id.org/sepses/resource/cpe/vendor/"+v.trim().replaceAll("\\s+","_").toLowerCase());
	         	 icsaModel.add(s, ICSA.HAS_VENDOR, rv);
	             icsaModel.add(rv, DCTerms.title, v.trim());
	             icsaModel.add(rv, RDF.type, CPE.VENDOR);
	             
	         
	        }
	       icsaModel.removeAll(null, ICSA.vendor, null);
	       
		}
	
	public static void createCompanyHeadquearterConnection(Model icsaModel) {	
		String q = "prefix icsa: <http://w3id.org/sepses/vocab/ref/icsa#>\r\n"
				+ "select ?s ?v WHERE{\r\n"
				+ "    ?s icsa:companyHeadquarter ?v;\r\n"
				+ "	\r\n"
				+ "}";
		
		ResultSet rs = queryLocalRepository(q, icsaModel);
	       while (rs.hasNext()) {
	            QuerySolution qsQuery = rs.nextSolution();
	            Resource s = qsQuery.get("?s").asResource();
	            String v = qsQuery.get("?v").toString();
	           
	            
	         	Resource rv = icsaModel.createResource("http://w3id.org/sepses/resource/icsa/companyHeadquarter/"+v.replaceAll("\\s+",""));
	         	 icsaModel.add(s, ICSA.HAS_COMPANY_HEADQUARTER, rv);
	             icsaModel.add(rv, DCTerms.title, v.trim());
	             icsaModel.add(rv, RDF.type, ICSA.COMPANY_HEADQUARTER);
	             
	         
	        }
	       icsaModel.removeAll(null, ICSA.companyHeadquarter, null);
	       
		}
	
	public static void createProductConnection(Model icsaModel) {	
		String q = "prefix icsa: <http://w3id.org/sepses/vocab/ref/icsa#>\r\n"
				+ "select ?s ?p WHERE{\r\n"
				+ "    ?s icsa:product ?p;\r\n"
				+ "	\r\n"
				+ "}";
		
		ResultSet rs = queryLocalRepository(q, icsaModel);
	       while (rs.hasNext()) {
	            QuerySolution qsQuery = rs.nextSolution();
	            Resource s = qsQuery.get("?s").asResource();
	            String pp = qsQuery.get("?p").toString();
	           
	            String[] ps = splitString(pp,"[,:;]");

	            
	             for (String p:ps) {
	            
	         	Resource rp = icsaModel.createResource("http://w3id.org/sepses/resource/cpe/product/"+p.trim().replaceAll("\\s+","_").toLowerCase().replaceAll("[^a-zA-Z0-9_-]", ""));
	         	 icsaModel.add(s, CPE.HAS_PRODUCT, rp);
	             icsaModel.add(rp, DCTerms.title, p.trim());
	             icsaModel.add(rp, RDF.type, CPE.PRODUCT);
	             
	             }
	         
	        }
	       icsaModel.removeAll(null, ICSA.product, null);
	       
		}
	
	public static void createProductDistributionConnection(Model icsaModel) {	
		String q = "prefix icsa: <http://w3id.org/sepses/vocab/ref/icsa#>\r\n"
				+ "select ?s ?p WHERE{\r\n"
				+ "    ?s icsa:productDistribution ?p;\r\n"
				+ "	\r\n"
				+ "}";
		
		ResultSet rs = queryLocalRepository(q, icsaModel);
	       while (rs.hasNext()) {
	            QuerySolution qsQuery = rs.nextSolution();
	            Resource s = qsQuery.get("?s").asResource();
	            String pp = qsQuery.get("?p").toString();
	           
	            String[] ps = splitString(pp,",");

	            
	             for (String p:ps) {
	            
	         	Resource rp = icsaModel.createResource("http://w3id.org/sepses/resource/icsa/productDistribution/"+p.trim().toLowerCase().replaceAll("\\s+","_"));
	         	 icsaModel.add(s, ICSA.HAS_PRODUCT_DISTRIBUTION, rp);
	             icsaModel.add(rp, DCTerms.title, p.trim());
	             icsaModel.add(rp, RDF.type, ICSA.PRODUCT_DISTRIBUTION);
	             
	             }
	         
	        }
	       icsaModel.removeAll(null, ICSA.productDistribution, null);
	       
		}

	
}
