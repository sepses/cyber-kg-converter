package ac.at.tuwien.ifs.sepses.parser.tool;

import ac.at.tuwien.ifs.sepses.storage.Storage;
import ac.at.tuwien.ifs.sepses.vocab.CPE;
import ac.at.tuwien.ifs.sepses.vocab.CVE;
import org.apache.commons.io.IOUtils;
import org.apache.jena.query.*;
import org.apache.jena.rdf.model.*;
import org.apache.jena.update.UpdateAction;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.UUID;

public class CVETool {

    private static final Logger log = LoggerFactory.getLogger(CVETool.class);

    public static ArrayList<String>[] checkExistingCVE(Storage storage, Model CVEModelTemp, String sparqlEndpoint,
            String CVEGraphName, Boolean isUseAuth, String user, String pass) throws IOException {

        //select all CVE on CVEModelTemp
        String queryTemp =
                "select distinct ?s ?id ?m where { ?s <http://w3id.org/sepses/vocab/ref/cve#id> ?id. ?s <http://purl.org/dc/terms/modified> ?m }";

        Query QTemp = QueryFactory.create(queryTemp);
        QueryExecution QTempEx = QueryExecutionFactory.create(QTemp, CVEModelTemp);
        ResultSet QTempResult = QTempEx.execSelect();
        Integer c = 0;
        ArrayList<String> CVELeave = new ArrayList<>();
        ArrayList<String> CVEUpdate = new ArrayList<>();
        ArrayList<String> CVEInsert = new ArrayList<>();
        ArrayList<String>[] CVEArray = new ArrayList[3];

        while (QTempResult.hasNext()) {
            QuerySolution QS1 = QTempResult.nextSolution();
            RDFNode cveRes = QS1.get("?s");
            RDFNode cveId = QS1.get("?id");
            RDFNode modifiedDate = QS1.get("?m");

            //check CVE is Exist
            String co = checkCVEExist(sparqlEndpoint, cveId.toString(), CVEGraphName);
            if (!co.equals("0^^http://www.w3.org/2001/XMLSchema#integer")) {
                //if yes check if CVE need ac.at.tuwien.ifs.sepses.processor
                String co2 =
                        checkCVENeedUpdate(sparqlEndpoint, cveId.toString(), modifiedDate.toString(), CVEGraphName);

                if (co2.equals("0^^http://www.w3.org/2001/XMLSchema#integer")) {
                    //need updates
                    CVEUpdate.add(cveId.toString());
                    deleteCVE(storage, sparqlEndpoint, cveRes.asResource(), CVEGraphName, isUseAuth, user, pass);
                } else {
                    //leave it
                    CVELeave.add(cveId.toString());
                }
            } else {
                //new cve!!, need insert
                CVEInsert.add(cveId.toString());
            }
            c++;
        }

        CVEArray[2] = CVELeave;
        CVEArray[1] = CVEUpdate;
        CVEArray[0] = CVEInsert;

        return CVEArray;
    }

    private static String checkCVEExist(String CyberKnowledgeEp, String Id, String CVEGraphName) {
        String queryCVE = "select (count(?s) as ?c)  from <" + CVEGraphName + "> where {"
                + "?s  a <http://w3id.org/sepses/vocab/ref/cve#CVE>."
                + "?s  <http://w3id.org/sepses/vocab/ref/cve#id> \"" + Id + "\"." + "}";

        Query QCVE = QueryFactory.create(queryCVE);
        QueryExecution qeQCVE = QueryExecutionFactory.sparqlService(CyberKnowledgeEp, QCVE);
        ResultSet rs = qeQCVE.execSelect();
        String c = "";
        while (rs.hasNext()) {
            QuerySolution qsQueryCPE = rs.nextSolution();
            RDFNode co = qsQueryCPE.get("?c");
            c = co.toString();
        }
        qeQCVE.close();
        return c;
    }

    private static String checkCVENeedUpdate(String CyberKnowledgeEp, String Id, String Modifdate,
            String CVEGraphName) {

        String queryCVE = "select (count(?s) as ?c) from <" + CVEGraphName + "> where {"
                + "?s  <http://w3id.org/sepses/vocab/ref/cve#id> \"" + Id + "\"."
                + "?s  <http://purl.org/dc/terms/modified> \"" + Modifdate + "\"." + "}";

        Query QCVE = QueryFactory.create(queryCVE);
        QueryExecution qeQCVE = QueryExecutionFactory.sparqlService(CyberKnowledgeEp, QCVE);
        ResultSet rs = qeQCVE.execSelect();
        String c = "";
        while (rs.hasNext()) {
            QuerySolution qsQueryCPE = rs.nextSolution();
            RDFNode co = qsQueryCPE.get("?c");
            c = co.toString();
        }
        qeQCVE.close();
        return c;
    }

    private static void deleteCVE(Storage storage, String endpoint, Resource cveInstance, String graphName,
            Boolean isUseAuth, String user, String pass) throws IOException {
        InputStream is = CVETool.class.getClassLoader().getResourceAsStream("sparql/deleteCVE.sparql");
        String query = IOUtils.toString(is, Charset.defaultCharset());
        is.close();

        ParameterizedSparqlString deleteQuery = new ParameterizedSparqlString(query);
        deleteQuery.setParam("graph", ResourceFactory.createResource(graphName));
        deleteQuery.setParam("cve", cveInstance);
        deleteQuery.setNsPrefix("cve", CVE.NS);

        storage.executeUpdate(endpoint, deleteQuery.toString(), isUseAuth, user, pass);

    }

    public static String readMetaSHA(String CVEMeta) {
        String metaSHA256 = "";
        try {

            InputStream fis = new FileInputStream(CVEMeta);
            InputStreamReader isr = new InputStreamReader(fis);
            BufferedReader reader = new BufferedReader(isr);
            String co = null;
            int c = 0;
            while ((co = reader.readLine()) != null) {
                c++;
                if (c == 5) {
                    metaSHA256 = co;
                }
            }
            reader.close();
            isr.close();
            fis.close();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return metaSHA256;
    }

    public static Model generateCVEMetaTriple(String metaSHA, int year) {
        Model CVEMetaModel = ModelFactory.createDefaultModel();
        Property metaSHA256 = CVE.META_SHA_256;
        Resource CVEMeta1 = CVEMetaModel.createResource(CVE.NS_INSTANCE + "meta/cveMeta" + year);
        CVEMetaModel.add(CVEMeta1, metaSHA256, metaSHA);
        return CVEMetaModel;

    }

    public static void deleteCVEMeta(Storage storage, String endpoint, String namegraph, boolean isUseAuth,
            String user, String pass) {
        Resource graphResource = ResourceFactory.createResource(namegraph);
        ParameterizedSparqlString query =
                new ParameterizedSparqlString("WITH ?g DELETE { ?s ?p ?o } WHERE { ?s ?p ?o }");
        query.setParam("p", CVE.META_SHA_256);
        query.setParam("g", graphResource);
        log.info(query.toString());

        storage.executeUpdate(endpoint, query.toString(), isUseAuth, user, pass);
    }
    
    public static void updateVulnerableConfigurationLinks(Model model) {
    	
    	String queryVC = "SELECT ?b WHERE { ?b a <http://w3id.org/sepses/vocab/ref/cve#VulnerableConfiguration> }";
    	  Query QVC = QueryFactory.create(queryVC);
          QueryExecution qeQVC = QueryExecutionFactory.create(QVC,model);
          ResultSet rs = qeQVC.execSelect();
//                   Integer count = 0;

                   ParameterizedSparqlString update =
                           new ParameterizedSparqlString("DELETE { ?s ?p ?b } INSERT {?s ?p ?b2} WHERE {?s ?p ?b} ");
                   ParameterizedSparqlString update2 =
                           new ParameterizedSparqlString("DELETE { ?b <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTest> ?s } INSERT { ?b2 <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTest> ?s } WHERE {?b <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTest>  ?s} ");
                   ParameterizedSparqlString update3 =
                           new ParameterizedSparqlString("DELETE { ?b <http://w3id.org/sepses/vocab/ref/cpe#logicalTestOperator> ?s } INSERT { ?b2 <http://w3id.org/sepses/vocab/ref/cpe#logicalTestOperator> ?s } WHERE {?b <http://w3id.org/sepses/vocab/ref/cpe#logicalTestOperator> ?s} ");
                   ParameterizedSparqlString update4 =
                           new ParameterizedSparqlString("DELETE { ?b <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTestFactRef> ?s } INSERT { ?b2 <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTestFactRef> ?s } WHERE {?b <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTestFactRef> ?s} ");
      
                   while (rs.hasNext()) {
        	 // System.out.println("mulai");
              QuerySolution qsQueryCPE = rs.nextSolution();
              //Resource s = qsQueryCPE.getResource("?s");
              Resource b = qsQueryCPE.getResource("?b");
              
              String uuid = generateUUID();
              Resource b2 = model.createResource(CVE.NS_INSTANCE+"VulnerableConfiguration/"+uuid);
             // System.out.println(s.toString());
            // System.out.println(b.toString());
              update.setNsPrefixes(model.getNsPrefixMap());
              update2.setNsPrefixes(model.getNsPrefixMap());
             // update.setParam("s", s);
              update.setParam("b", b);
              update.setParam("b2", b2);
              update2.setParam("b", b);
              update2.setParam("b2", b2);
              update3.setParam("b", b);
              update3.setParam("b2", b2);
              update4.setParam("b", b);
              update4.setParam("b2", b2);
              
              UpdateRequest updateRequest = UpdateFactory.create(update.toString());
              UpdateAction.execute(updateRequest, model);
              UpdateRequest updateRequest2 = UpdateFactory.create(update2.toString());
              UpdateAction.execute(updateRequest2, model);
              UpdateRequest updateRequest3 = UpdateFactory.create(update3.toString());
              UpdateAction.execute(updateRequest3, model);
              UpdateRequest updateRequest4 = UpdateFactory.create(update4.toString());
              UpdateAction.execute(updateRequest4, model);
           
              
              
             
          }
      //System.out.println("jumlah data"+count);
      // System.out.println("berhasil");
      //model.write(System.out,"TURTLE");
	
    	
    }
    

    
    
 public static void updateLogicalTestLinks(Model model) {
    	
    	String queryVC = "SELECT ?b WHERE { ?b a <http://w3id.org/sepses/vocab/ref/cpe#LogicalTest> }";
    	  Query QVC = QueryFactory.create(queryVC);
          QueryExecution qeQVC = QueryExecutionFactory.create(QVC,model);
          ResultSet rs = qeQVC.execSelect();
//                   Integer count = 0;

                   ParameterizedSparqlString update =
                           new ParameterizedSparqlString("DELETE { ?s ?p ?b } INSERT {?s ?p ?b2} WHERE {?s ?p ?b} ");
                   ParameterizedSparqlString update2 =
                           new ParameterizedSparqlString("DELETE { ?b <http://w3id.org/sepses/vocab/ref/cpe#logicalTestNegate> ?s } INSERT { ?b2 <http://w3id.org/sepses/vocab/ref/cpe#logicalTestNegate> ?s } WHERE {?b <http://w3id.org/sepses/vocab/ref/cpe#logicalTestNegate>  ?s} ");
                   ParameterizedSparqlString update3 =
                           new ParameterizedSparqlString("DELETE { ?b <http://w3id.org/sepses/vocab/ref/cpe#logicalTestOperator> ?s } INSERT { ?b2 <http://w3id.org/sepses/vocab/ref/cpe#logicalTestOperator> ?s } WHERE {?b <http://w3id.org/sepses/vocab/ref/cpe#logicalTestOperator> ?s} ");
                   ParameterizedSparqlString update4 =
                           new ParameterizedSparqlString("DELETE { ?b <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTestFactRef> ?s } INSERT { ?b2 <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTestFactRef> ?s } WHERE {?b <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTestFactRef> ?s} ");
      
                   while (rs.hasNext()) {
        	 // System.out.println("mulai");
              QuerySolution qsQueryCPE = rs.nextSolution();
              //Resource s = qsQueryCPE.getResource("?s");
              Resource b = qsQueryCPE.getResource("?b");
              
              String uuid = generateUUID();
              Resource b2 = model.createResource(CPE.NS_INSTANCE+"LogicalTest/"+uuid);
             // System.out.println(s.toString());
            // System.out.println(b.toString());
              update.setNsPrefixes(model.getNsPrefixMap());
              update2.setNsPrefixes(model.getNsPrefixMap());
             // update.setParam("s", s);
              update.setParam("b", b);
              update.setParam("b2", b2);
              update2.setParam("b", b);
              update2.setParam("b2", b2);
              update3.setParam("b", b);
              update3.setParam("b2", b2);
              update4.setParam("b", b);
              update4.setParam("b2", b2);

              
              UpdateRequest updateRequest = UpdateFactory.create(update.toString());
              UpdateAction.execute(updateRequest, model);
              UpdateRequest updateRequest2 = UpdateFactory.create(update2.toString());
              UpdateAction.execute(updateRequest2, model);
              UpdateRequest updateRequest3 = UpdateFactory.create(update3.toString());
              UpdateAction.execute(updateRequest3, model);
              UpdateRequest updateRequest4 = UpdateFactory.create(update4.toString());
              UpdateAction.execute(updateRequest4, model);

              
              
             
          }
//      System.out.println("jumlah data"+count);
//       System.out.println("berhasil");
//      model.write(System.out,"TURTLE");
	
    	
    }
 
 public static void deleteType(Model model) {
	 ParameterizedSparqlString update =
             new ParameterizedSparqlString("DELETE { ?s a <http://w3id.org/sepses/vocab/ref/cve#VulnerableConfiguration> } WHERE {?s a <http://w3id.org/sepses/vocab/ref/cve#VulnerableConfiguration>} ");
	 ParameterizedSparqlString update2 =
             new ParameterizedSparqlString("DELETE { ?s  a   <http://w3id.org/sepses/vocab/ref/cpe#LogicalTest> } WHERE {?s  a  <http://w3id.org/sepses/vocab/ref/cpe#LogicalTest>}");
	 UpdateRequest updateRequest = UpdateFactory.create(update.toString());
     UpdateAction.execute(updateRequest, model);
     UpdateRequest updateRequest2 = UpdateFactory.create(update2.toString());
     UpdateAction.execute(updateRequest2, model);
}
 
 public static void setType(Model model) {
	 String queryVC = "SELECT ?b WHERE { ?s <http://w3id.org/sepses/vocab/ref/cve#hasVulnerableConfiguration> ?b }";
	  Query QVC = QueryFactory.create(queryVC);
     QueryExecution qeQVC = QueryExecutionFactory.create(QVC,model);
     ResultSet rs = qeQVC.execSelect();
     ParameterizedSparqlString update =
             new ParameterizedSparqlString("INSERT { ?b a <http://w3id.org/sepses/vocab/ref/cve#VulnerableConfiguration> } WHERE {} ");
    
     while (rs.hasNext()) {
    	    QuerySolution qsQueryCPE = rs.nextSolution();
            Resource b = qsQueryCPE.getResource("?b");
            update.setNsPrefixes(model.getNsPrefixMap());
            update.setParam("b", b);
            UpdateRequest updateRequest = UpdateFactory.create(update.toString());
            UpdateAction.execute(updateRequest, model);
     }
	 
	 
    
 }
 public static void setType2(Model model) {
	 String queryVC = "SELECT ?b WHERE { ?s <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTest> ?b }";
	  Query QVC = QueryFactory.create(queryVC);
     QueryExecution qeQVC = QueryExecutionFactory.create(QVC,model);
     ResultSet rs = qeQVC.execSelect();
     ParameterizedSparqlString update =
             new ParameterizedSparqlString("INSERT { ?b a <http://w3id.org/sepses/vocab/ref/cpe#LogicalTest> } WHERE {} ");
    
     while (rs.hasNext()) {
    	    QuerySolution qsQueryCPE = rs.nextSolution();
            Resource b = qsQueryCPE.getResource("?b");
            update.setNsPrefixes(model.getNsPrefixMap());
            update.setParam("b", b);
            UpdateRequest updateRequest = UpdateFactory.create(update.toString());
            UpdateAction.execute(updateRequest, model);
     }
	 
	 
    
 }
 
 public static void cpeDecode(Model model) throws UnsupportedEncodingException {
	 String queryVC = "SELECT ?s WHERE { ?s a  <http://w3id.org/sepses/vocab/ref/cpe#CPE> }";
	  Query QVC = QueryFactory.create(queryVC);
     QueryExecution qeQVC = QueryExecutionFactory.create(QVC,model);
     ResultSet rs = qeQVC.execSelect();
     ParameterizedSparqlString update =
             new ParameterizedSparqlString("DELETE { ?s <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTestFactRef> ?b }  INSERT { ?s <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTestFactRef> ?b2} WHERE {?s <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTestFactRef> ?b} ") ;
     ParameterizedSparqlString update2 =
             new ParameterizedSparqlString("DELETE { ?b <http://w3id.org/sepses/vocab/ref/cpe#cpe23> ?o }  INSERT { ?b2 <http://w3id.org/sepses/vocab/ref/cpe#cpe23> ?o } WHERE {?b <http://w3id.org/sepses/vocab/ref/cpe#cpe23> ?o } ") ;
   
     while (rs.hasNext()) {
    	    QuerySolution qsQueryCPE = rs.nextSolution();
            Resource b = qsQueryCPE.getResource("?s");
           // Resource s = qsQueryCPE.getResource("?s");
        
           // update.setParam("s", s);
           // System.out.println(b.toString());
            String sb2 = java.net.URLDecoder.decode(b.toString(), StandardCharsets.UTF_8.name());
           // System.out.println(sb2);
           // System.out.println(sb2.toString());
            String cpens = CPE.NS_INSTANCE;
           
            String ssb2= sb2.substring(cpens.length());
            //System.out.println(ssb2.toString());
            String sssb2 = ssb2.replace("2.3","").replaceAll("[:*\\\\()-//</>\"\'^|]", "");
           Resource b2 = model.createResource(CPE.NS_INSTANCE+sssb2);
            //System.out.println(sssb2);
            update.setNsPrefixes(model.getNsPrefixMap());
            update.setParam("b", b);
            update.setParam("b2", b2);
            UpdateRequest updateRequest = UpdateFactory.create(update.toString());
            UpdateAction.execute(updateRequest, model);
            
            update2.setNsPrefixes(model.getNsPrefixMap());
            update2.setParam("b", b);
            update2.setParam("b2", b2);
            UpdateRequest updateRequest2 = UpdateFactory.create(update2.toString());
            UpdateAction.execute(updateRequest2, model);
            
            model.add(generateAdditionalTriples(model, ssb2, b2));
            
     }
	 
     deleteTypeCPE(model);
     setTypeCPE(model);

 }
 
 public static Model generateAdditionalTriples(Model CPEModel, String cpe23s, Resource resource) {

     //query to cpeModel
     Model additionalCPEModel = ModelFactory.createDefaultModel();

//         String cpe1 = cpe23s.substring(0, cpe23s.indexOf(":"));
         String cpe1a = cpe23s.substring(cpe23s.indexOf(":") + 1, cpe23s.length());
         String cpe2 = cpe1a.substring(0, cpe1a.indexOf(":"));
         String cpe2a = cpe1a.substring(cpe1a.indexOf(":") + 1, cpe1a.length());
         String cpe3 = cpe2a.substring(0, cpe2a.indexOf(":"));
         String cpe3a = cpe2a.substring(cpe2a.indexOf(":") + 1, cpe2a.length());
         String cpe4 = cpe3a.substring(0, cpe3a.indexOf(":"));
         String cpe4a = cpe3a.substring(cpe3a.indexOf(":") + 1, cpe3a.length());
         String cpe5 = cpe4a.substring(0, cpe4a.indexOf(":"));
         String cpe5a = cpe4a.substring(cpe4a.indexOf(":") + 1, cpe4a.length());
         String cpe6 = cpe5a.substring(0, cpe5a.indexOf(":"));
         String cpe6a = cpe5a.substring(cpe5a.indexOf(":") + 1, cpe5a.length());
         String cpe7 = cpe6a.substring(0, cpe6a.indexOf(":"));
         String cpe7a = cpe6a.substring(cpe6a.indexOf(":") + 1, cpe6a.length());
         String cpe8 = cpe7a.substring(0, cpe7a.indexOf(":"));
         String cpe8a = cpe7a.substring(cpe7a.indexOf(":") + 1, cpe7a.length());
         String cpe9 = cpe8a.substring(0, cpe8a.indexOf(":"));
         String cpe9a = cpe8a.substring(cpe8a.indexOf(":") + 1, cpe8a.length());
         String cpe10 = cpe9a.substring(0, cpe9a.indexOf(":"));
         String cpe10a = cpe9a.substring(cpe9a.indexOf(":") + 1, cpe9a.length());
         String cpe11 = cpe10a.substring(0, cpe10a.indexOf(":"));
         String cpe11a = cpe10a.substring(cpe10a.indexOf(":") + 1, cpe10a.length());
         String cpe12 = cpe11a.substring(0, cpe11a.indexOf(":"));
         
         Resource vendor = CPEModel.createResource(CPE.NS_INSTANCE+"vendor/"+cpe4.replaceAll("[:*\\\\()<>\"\'^|]", ""));
         Resource product = CPEModel.createResource(CPE.NS_INSTANCE+"product/"+cpe5.replaceAll("[:*\\\\()<>\"\'^|]", ""));

         resource.addProperty(CPE.CPE_VERSION, cpe2);
         resource.addProperty(CPE.PART, cpe3);
         resource.addProperty(CPE.HAS_VENDOR, vendor);
         resource.addProperty(CPE.HAS_PRODUCT, product);
         resource.addProperty(CPE.VERSION, cpe6);
         resource.addProperty(CPE.UPDATE, cpe7);
         resource.addProperty(CPE.EDITION, cpe8);
         resource.addProperty(CPE.LANGUAGE, cpe9);
         resource.addProperty(CPE.SOFTWARE_EDITION, cpe10);
         resource.addProperty(CPE.TARGET_SOFTWARE, cpe11);
         resource.addProperty(CPE.TARGET_HARDWARE, cpe10);
         resource.addProperty(CPE.OTHER, cpe12);
       return additionalCPEModel;
 }
 
 public static void deleteTypeCPE(Model model) {
	 ParameterizedSparqlString update =
             new ParameterizedSparqlString("DELETE { ?s a <http://w3id.org/sepses/vocab/ref/cpe#CPE> } WHERE {?s a <http://w3id.org/sepses/vocab/ref/cpe#CPE>} ");
	     	 UpdateRequest updateRequest = UpdateFactory.create(update.toString());
     UpdateAction.execute(updateRequest, model);
}
 
 public static void setTypeCPE(Model model) {
	 String queryVC = "SELECT ?b WHERE { ?s <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTestFactRef> ?b }";
	  Query QVC = QueryFactory.create(queryVC);
     QueryExecution qeQVC = QueryExecutionFactory.create(QVC,model);
     ResultSet rs = qeQVC.execSelect();
     ParameterizedSparqlString update =
             new ParameterizedSparqlString("INSERT { ?b a <http://w3id.org/sepses/vocab/ref/cpe#CPE> } WHERE {} ");
    
     while (rs.hasNext()) {
    	    QuerySolution qsQueryCPE = rs.nextSolution();
            Resource b = qsQueryCPE.getResource("?b");
            update.setNsPrefixes(model.getNsPrefixMap());
            update.setParam("b", b);
            UpdateRequest updateRequest = UpdateFactory.create(update.toString());
            UpdateAction.execute(updateRequest, model);
     }
	 
	 
    
 }
    public static String generateUUID() {
    	UUID uuid = UUID.randomUUID();
    	return uuid.toString();
    }

}
