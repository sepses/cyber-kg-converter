package ac.at.tuwien.ifs.sepses.processor.updater;

import org.apache.jena.query.*;
import org.apache.jena.rdf.model.*;
import org.apache.jena.update.UpdateExecutionFactory;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateProcessor;
import org.apache.jena.update.UpdateRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;

public class CVEUpdate {

    private static final Logger log = LoggerFactory.getLogger(CVEUpdate.class);

    public static ArrayList<String>[] checkExistingCVE(Model CVEModelTemp, String CyberKnowledgeEp,
            String CVEGraphName) {
        //1. select all CVE on CVEModelTemp

        String queryTemp = "select distinct ?s ?id ?m where {" + "?s <http://w3id.org/sepses/vocab/ref/cve#id> ?id."
                + "?s <http://purl.org/dc/terms/modified> ?m }";
        //log.info(queryTemp);//System.exit(0);
        Query QTemp = QueryFactory.create(queryTemp);
        QueryExecution QTempEx = QueryExecutionFactory.create(QTemp, CVEModelTemp);
        ResultSet QTempResult = QTempEx.execSelect();
        Integer c = 0;
        ArrayList<String> CVELeave = new ArrayList<String>();
        ArrayList<String> CVEUpdate = new ArrayList<String>();
        ArrayList<String> CVEInsert = new ArrayList<String>();
        ArrayList<String>[] CVEArray = new ArrayList[3];
        while (QTempResult.hasNext()) {
            QuerySolution QS1 = QTempResult.nextSolution();
            RDFNode cveRes = QS1.get("?s");
            RDFNode cveId = QS1.get("?id");
            RDFNode modifiedDate = QS1.get("?m");
            //check CVE is Exist

            String co = checkCVEExist(CyberKnowledgeEp, cveId.toString(), CVEGraphName);
            //log.info(co);//System.exit(0);
            //Integer co = 0;

            if (!co.equals("0^^http://www.w3.org/2001/XMLSchema#integer")) {
                //if yes check if CVE need ac.at.tuwien.ifs.sepses.processor
                //log.info("checkCVENeedUpdate");
                String co2 =
                        checkCVENeedUpdate(CyberKnowledgeEp, cveId.toString(), modifiedDate.toString(), CVEGraphName);

                if (co2.equals("0^^http://www.w3.org/2001/XMLSchema#integer")) {
                    //log.info("CVENeedUpdate");
                    //need ac.at.tuwien.ifs.sepses.processor
                    CVEUpdate.add(cveId.toString());
                    //	log.info("delete existing CVE...");
                    deleteCVE(CyberKnowledgeEp, cveRes.toString(), CVEGraphName);
                } else {
                    //leave it
                    CVELeave.add(cveId.toString());
                }
            } else {
                //new cve!!, need insert
                //log.info("CVE is New, NeedInsert");
                CVEInsert.add(cveId.toString());

            }
            c++;

        }

        CVEArray[2] = CVELeave;
        CVEArray[1] = CVEUpdate;
        CVEArray[0] = CVEInsert;
        //log.info(c);
        return CVEArray;
    }

    private static String checkCVEExist(String CyberKnowledgeEp, String Id, String CVEGraphName) {
        String queryCVE = "select (count(?s) as ?c)  from <" + CVEGraphName + "> where {"
                + "?s  a <http://w3id.org/sepses/vocab/ref/cve#CVE>."
                + "?s  <http://w3id.org/sepses/vocab/ref/cve#id> \"" + Id + "\"." + "}";
        //	log.info(queryCVE);
        //System.exit(0);

        Query QCVE = QueryFactory.create(queryCVE);
        QueryExecution qeQCVE = QueryExecutionFactory.sparqlService(CyberKnowledgeEp, QCVE);
        //((QueryEngineHTTP)qeQueryCPE).addParam("timeout", "10000");
        ResultSet rsQCVE = qeQCVE.execSelect();
        String c = "";
        while (rsQCVE.hasNext()) {
            QuerySolution qsQueryCPE = rsQCVE.nextSolution();
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
        ResultSet rsQCVE = qeQCVE.execSelect();
        String c = "";
        while (rsQCVE.hasNext()) {
            QuerySolution qsQueryCPE = rsQCVE.nextSolution();
            RDFNode co = qsQueryCPE.get("?c");
            c = co.toString();
        }
        qeQCVE.close();
        return c;
    }

    private static void deleteCVE(String CyberKnowledgeEp, String cveId, String CVEGraphName) {
        String cveRes = "<" + cveId + ">";
        //level 1 deep
        String deleteQuery1 =
                "with  <" + CVEGraphName + "> DELETE { ?s ?p ?o }  \r\n" + "WHERE { ?s ?p ?o. " + "filter (?s = "
                        + cveRes + ")}";
        //level 2 deep
        String deleteQuery2 =
                "with <" + CVEGraphName + "> DELETE { ?o ?p1 ?o1 }  \r\n" + "WHERE { ?s ?p ?o. " + " ?o ?p1 ?o1. "
                        + "filter (?s = " + cveRes + ")}";
        //level 3 deep
        String deleteQuery3 =
                "with <" + CVEGraphName + "> DELETE { ?o1 ?p2 ?o2 }  \r\n" + "WHERE { ?s ?p ?o. " + " ?o ?p1 ?o1. "
                        + " ?o1 ?p2 ?o2. " + "filter (?s = " + cveRes + ")}";

        UpdateRequest QCVE1 = UpdateFactory.create(deleteQuery3);
        UpdateProcessor qeQCVE1 = UpdateExecutionFactory.createRemote(QCVE1, CyberKnowledgeEp);
        qeQCVE1.execute();
        UpdateRequest QCVE2 = UpdateFactory.create(deleteQuery2);
        UpdateProcessor qeQCVE2 = UpdateExecutionFactory.createRemote(QCVE2, CyberKnowledgeEp);
        qeQCVE2.execute();
        UpdateRequest QCVE3 = UpdateFactory.create(deleteQuery1);
        UpdateProcessor qeQCVE3 = UpdateExecutionFactory.createRemote(QCVE3, CyberKnowledgeEp);
        qeQCVE3.execute();

    }

    public static boolean checkSHAMeta(String SHA256, String CyberKnowledgeEp, String namegraph) {
        String Query = "select (count(?s) as ?c) from <" + namegraph + "> where {"
                + "?s <http://w3id.org/sepses/vocab/ref/cve#metaSHA256>  \"" + SHA256 + "\" }";
        log.info(Query);//System.exit(0);
        Query qfQuery = QueryFactory.create(Query);
        QueryExecution qeQuery = QueryExecutionFactory.sparqlService(CyberKnowledgeEp, qfQuery);
        ResultSet rsQuery = qeQuery.execSelect();
        boolean found = true;
        while (rsQuery.hasNext()) {
            QuerySolution qsQuery = rsQuery.nextSolution();
            RDFNode c = qsQuery.get("c");
            //log.info(c.toString());System.exit(0);
            if (c.toString().equals("0^^http://www.w3.org/2001/XMLSchema#integer")) {
                found = false;
            }
        }
        return found;

    }

    public static String readMetaSHA(String CVEMeta) {
        String metaSHA256 = "";
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(CVEMeta)));
            String co = null;
            int c = 0;
            while ((co = reader.readLine()) != null) {
                c++;
                if (c == 5) {
                    metaSHA256 = co;
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return metaSHA256;
    }

    public static org.apache.jena.rdf.model.Model generateCVEMetaTriple(String metaSHA) {
        org.apache.jena.rdf.model.Model CVEMetaModel = ModelFactory.createDefaultModel();
        Property metaSHA256 = CVEMetaModel.createProperty("http://w3id.org/sepses/vocab/ref/cve#metaSHA256");
        Resource CVEMeta1 = CVEMetaModel.createResource("http://w3id.org/sepses/resource/cve/meta/cveMeta1");
        CVEMetaModel.add(CVEMeta1, metaSHA256, metaSHA);
        return CVEMetaModel;

    }

    public static void deleteCVEMeta(String CyberKnowledgeEp, String Namegraph) {
        String p = "<http://w3id.org/sepses/vocab/ref/cve#metaSHA256>";
        String Query =
                "with  <" + Namegraph + "> DELETE { ?s ?p ?o }  \r\n" + "WHERE { ?s ?p ?o. " + "filter (?p = " + p
                        + ")}";
        UpdateRequest QCVE1 = UpdateFactory.create(Query);
        UpdateProcessor qeQCVE1 = UpdateExecutionFactory.createRemote(QCVE1, CyberKnowledgeEp);
        qeQCVE1.execute();
    }

}
