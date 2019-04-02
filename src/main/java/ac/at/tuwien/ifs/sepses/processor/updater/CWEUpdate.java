package ac.at.tuwien.ifs.sepses.processor.updater;

import ac.at.tuwien.ifs.sepses.rml.XMLParser;
import org.apache.jena.query.*;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.update.UpdateExecutionFactory;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateProcessor;
import org.apache.jena.update.UpdateRequest;

import java.io.IOException;
import java.util.ArrayList;

public class CWEUpdate {

    public static void updateCWE(Model cWEModel, String cyberKnowledgeEp, String graphname) {
        //select cwe from triple store => save to array (1)
        ArrayList<String>[] CWEResArray = getAllExistingCWE(cyberKnowledgeEp, graphname);
        //select cwe from cwemodel  (2)
        String sidQuery = "select  ?s (count(?mdate) as ?dc) where {\r\n"
                + "    ?s a <http://w3id.org/sepses/vocab/ref/cwe#CWE>.\r\n"
                + "    ?s <http://purl.org/dc/terms/modified> ?mdate.\r\n" + "} \r\n" + "GROUP BY ?s";

        //	System.out.println(sidQuery);System.exit(0);

        Query sidQ = QueryFactory.create(sidQuery);
        QueryExecution sidQex = QueryExecutionFactory.create(sidQ, cWEModel);
        // ((QueryEngineHTTP)sidQex).addParam("timeout", "10000");
        ResultSet sidQResult = sidQex.execSelect();
        int del = 0;
        while (sidQResult.hasNext()) {
            QuerySolution sidQS = sidQResult.nextSolution();
            RDFNode CWERes = sidQS.get("s");
            RDFNode CWEdc = sidQS.get("dc");
            //System.out.println(CWERes.toString());System.exit(0);
            //for each cwe compare if cwe in cwe model (2) exist in cwe array (1), if yes
            if (CWEResArray[0].contains(CWERes.toString())) {
                //check if modification are the same, if no

                int key = CWEResArray[0].indexOf(CWERes.toString());
                //System.out.println(key);System.exit(0);
                if (CWEResArray[1].get(key).equals(CWEdc.toString())) {
                    //leave it
                } else {
                    //delete cwe from (1) => log it
                    //System.out.println("delete!!");
                    deleteCWE(cyberKnowledgeEp, graphname, CWERes.toString());
                    del++;
                }

            } else {
                //leave it
            }

            //System.out.println(CPERes.toString());
        }
        System.out.println("updated CPE= " + del);

        //if yes => leave it
        //if no, => log it as new cwe

    }

    private static void deleteCWE(String cyberKnowledgeEp, String graphname, String CWEId) {
        String cweRes = "<" + CWEId + ">";
        //level 1 deep
        String deleteQuery1 =
                "with  <" + graphname + "> DELETE { ?s ?p ?o }  \r\n" + "WHERE { ?s ?p ?o. " + "filter (?s = "
                        + cweRes + ")}";
        //level 2 deep
        String deleteQuery2 =
                "with <" + graphname + "> DELETE { ?o ?p1 ?o1 }  \r\n" + "WHERE { ?s ?p ?o. " + " ?o ?p1 ?o1. "
                        + "filter (?s = " + cweRes + ")}";
        //level 3 deep
        String deleteQuery3 =
                "with <" + graphname + "> DELETE { ?o1 ?p2 ?o2 }  \r\n" + "WHERE { ?s ?p ?o. " + " ?o ?p1 ?o1. "
                        + " ?o1 ?p2 ?o2. " + "filter (?s = " + cweRes + ")}";
        //System.out.println(deleteQuery1);

        //System.out.println(deleteQuery2);
        //System.out.println(deleteQuery3);
        //System.exit(0);
        UpdateRequest QCWE1 = UpdateFactory.create(deleteQuery3);
        UpdateProcessor qeQCWE1 = UpdateExecutionFactory.createRemote(QCWE1, cyberKnowledgeEp);
        qeQCWE1.execute();
        UpdateRequest QCWE2 = UpdateFactory.create(deleteQuery2);
        UpdateProcessor qeQCWE2 = UpdateExecutionFactory.createRemote(QCWE2, cyberKnowledgeEp);
        qeQCWE2.execute();
        UpdateRequest QCWE3 = UpdateFactory.create(deleteQuery1);
        UpdateProcessor qeQCWE3 = UpdateExecutionFactory.createRemote(QCWE3, cyberKnowledgeEp);
        qeQCWE3.execute();

    }

    private static ArrayList<String>[] getAllExistingCWE(String cyberKnowledgeEp, String graphname) {

        //query to get cveId property from snort rule
        String sidQuery = "select ?s (count(?mdate) as ?dc) from <" + graphname + "> where {\r\n"
                + "    ?s a <http://w3id.org/sepses/vocab/ref/cwe#CWE>.\r\n"
                + "    ?s <http://purl.org/dc/terms/modified> ?mdate.\r\n" + "} \r\n" + "GROUP BY ?s";

        //System.out.println(sidQuery);System.exit(0);

        Query sidQ = QueryFactory.create(sidQuery);
        QueryExecution sidQex = QueryExecutionFactory.sparqlService(cyberKnowledgeEp, sidQ);
        // ((QueryEngineHTTP)sidQex).addParam("timeout", "10000");
        ResultSet sidQResult = sidQex.execSelect();

        //System.exit(0);
        ArrayList<String> CWEResArray = new ArrayList<String>();
        ArrayList<String> CWEdc = new ArrayList<String>();
        ArrayList<String>[] CWEArrayOfList = new ArrayList[2];
        while (sidQResult.hasNext()) {
            QuerySolution sidQS = sidQResult.nextSolution();
            RDFNode CWERes = sidQS.get("s");
            RDFNode dc = sidQS.get("dc");
            CWEResArray.add(CWERes.toString());
            CWEdc.add(dc.toString());

            //System.out.println(CPERes.toString());
        }
        CWEArrayOfList[0] = CWEResArray;
        CWEArrayOfList[1] = CWEdc;

        //CAPECModel.close();
        // System.exit(0);
        return CWEArrayOfList;
    }

    public static boolean checkIsUptodate(String RMLTemp, String CWEXML, String CyberKnowledgeEp, String graphname)
            throws IOException {

        Model CWETemp = XMLParser.Parse(CWEXML, RMLTemp);

        String Query1 = "select ?s from <" + graphname + "> where {\r\n"
                + "?s a <http://w3id.org/sepses/vocab/ref/cwe#WeaknessCatalog>\r\n" + "}";
        //System.out.println(Query1);System.exit(0);
        Query qfQuery1 = QueryFactory.create(Query1);
        QueryExecution qeQuery1 = QueryExecutionFactory.sparqlService(CyberKnowledgeEp, qfQuery1);
        ResultSet rsQuery1 = qeQuery1.execSelect();
        String s = "";
        while (rsQuery1.hasNext()) {
            QuerySolution qsQueryCPE = rsQuery1.nextSolution();
            RDFNode cat = qsQueryCPE.get("?s");
            s = cat.toString();
        }

        String Query2 =
                "select ?s where {\r\n" + "?s a <http://w3id.org/sepses/vocab/ref/cwe#WeaknessCatalog>\r\n" + "}";
        //System.out.println(Query1);System.exit(0);
        Query qfQuery2 = QueryFactory.create(Query2);
        QueryExecution qeQuery2 = QueryExecutionFactory.create(qfQuery2, CWETemp);
        ResultSet rsQuery2 = qeQuery2.execSelect();
        String s2 = "";
        while (rsQuery2.hasNext()) {
            QuerySolution qsQueryCPE2 = rsQuery2.nextSolution();
            RDFNode cat2 = qsQueryCPE2.get("?s");
            s2 = cat2.toString();
        }
        if (s.equals(s2)) {
            return true;
        } else {
            return false;
        }

    }

    public static String checkExistingTriple(String CyberKnowledgeEp, String graphname) {
        //select if resource is not empty
        String Query1 = "select (str(count(?s)) as ?c) from <" + graphname + "> where {\r\n"
                + "?s a <http://w3id.org/sepses/vocab/ref/cwe#CWE>\r\n" + "}";
        //System.out.println(Query1);System.exit(0);
        Query qfQuery1 = QueryFactory.create(Query1);
        QueryExecution qeQuery1 = QueryExecutionFactory.sparqlService(CyberKnowledgeEp, qfQuery1);
        ResultSet rsQuery1 = qeQuery1.execSelect();
        String c = "";
        while (rsQuery1.hasNext()) {
            QuerySolution qsQueryCPE = rsQuery1.nextSolution();
            RDFNode cwe = qsQueryCPE.get("c");
            c = cwe.toString();
        }
        return c;

    }

    public static String countCWE(Model CWEModel) {
        //select if resource is not empty
        String Query1 =
                "select (str(count(?s)) as ?c) where {\r\n" + "?s a <http://w3id.org/sepses/vocab/ref/cwe#CWE>\r\n"
                        + "}";
        //System.out.println(Query1);System.exit(0);
        Query qfQuery1 = QueryFactory.create(Query1);
        QueryExecution qeQuery1 = QueryExecutionFactory.create(qfQuery1, CWEModel);
        ResultSet rsQuery1 = qeQuery1.execSelect();
        String c = "";
        while (rsQuery1.hasNext()) {
            QuerySolution qsQueryCWE = rsQuery1.nextSolution();
            RDFNode cwe = qsQueryCWE.get("c");
            c = cwe.toString();
        }

        return c;

    }
}
