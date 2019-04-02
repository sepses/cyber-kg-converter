package ac.at.tuwien.ifs.sepses.linking;

import org.apache.jena.query.*;
import org.apache.jena.rdf.model.*;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

public class CWELinking {

    public static Model generateLinking(Model CWEModel, String CyberKnowledgeEp, String CAPECGraphName,
            String fileName, String outputDir) throws IOException {

        ArrayList<String>[] CAPECResArray = getAllCAPEC(CyberKnowledgeEp, CAPECGraphName);
        //System.out.println(CAPECResArray[0].size());System.exit(0);

        String sidQuery =
                "select ?s where {\r\n" + "    	?s a <http://w3id.org/sepses/vocab/ref/cwe#CWE>.\r\n" + "}";

        Query sidQ = QueryFactory.create(sidQuery);
        QueryExecution sidQex = QueryExecutionFactory.create(sidQ, CWEModel);
        ResultSet sidQResult = sidQex.execSelect();

        Model linkingModel = ModelFactory.createDefaultModel();
        Model NolinkingModel = ModelFactory.createDefaultModel();
        while (sidQResult.hasNext()) {
            QuerySolution sidQS = sidQResult.nextSolution();
            RDFNode CWEId = sidQS.get("s");
            //2. for each subject result, select all CAPEC that the subject connect to
            String Query2 = "select ?capecId where {  \r\n"
                    + "?s <http://w3id.org/sepses/vocab/ref/cwe#capecId> ?capecId. \r\n" + "filter (?s = <" + CWEId
                    + ">) . \r\n" + "}";

            //System.out.println(Query2);System.exit(0);

            Query Q2 = QueryFactory.create(Query2);
            QueryExecution Qex2 = QueryExecutionFactory.create(Q2, CWEModel);
            ResultSet QResult2 = Qex2.execSelect();
            Property hasCAPEC = linkingModel.createProperty("http://w3id.org/sepses/vocab/ref/cwe#hasCAPEC");
            Property hasNoCAPEC = linkingModel.createProperty("http://w3id.org/sepses/vocab/ref/cwe#hasNoCAPEC");
            int i = 0;
            int capecGiven = 0;
            int capecFound = 0;
            int capecNotFound = 0;
            while (QResult2.hasNext()) {
                QuerySolution QS2 = QResult2.nextSolution();
                RDFNode capecId = QS2.get("?capecId");
                // System.out.println(CAPECResArray[1].get(i));
                //check in foundCPE array
                if (CAPECResArray[1].contains(capecId.toString())) {
                    int key = CAPECResArray[1].indexOf(capecId.toString());
                    Resource resS = linkingModel.createResource(CWEId.toString());
                    Resource resO = linkingModel.createResource(CAPECResArray[0].get(key));
                    resS.addProperty(hasCAPEC, resO);
                    capecFound++;
                } else {
                    Resource resSn = NolinkingModel.createResource(CWEId.toString());
                    resSn.addProperty(hasNoCAPEC, capecId);
                    capecNotFound++;
                }
                capecGiven++;
            }

            System.out.println(
                    "CAPEC Found :" + capecFound + ", CAPEC Not Found : " + capecNotFound + ", CAPEC Given :"
                            + capecGiven);

        }
        String fileNameNL =
                outputDir + "/ac/at/tuwien/ifs/sepses/linking/CWETOCAPEC_" + fileName + "_NoLinking.log.ttl";
        // FileWriter rdfLinking = new FileWriter(fileName);
        FileWriter nolinkingCVECWELog = new FileWriter(fileNameNL);

        try {
            NolinkingModel.write(nolinkingCVECWELog, "TURTLE");
            //	nolinkingCVECWELog.write(nolinking_cve_cwe);
        } finally {
            //linkingModel.close();
        }

        //CWEModel.close();

        return linkingModel;

    }

    public static ArrayList<String>[] getAllCAPEC(String CyberKnowledgeEp, String CAPECGraphName) {

        //0. Select all capecId and capec resource from CAPEC
        String QueryCAPEC = "select distinct ?s ?id from <" + CAPECGraphName + "> where {\r\n"
                + "    ?s a <http://w3id.org/sepses/vocab/ref/capec#CAPEC>.\r\n"
                + "    ?s <http://w3id.org/sepses/vocab/ref/capec#id> ?id .\r\n" + "  } ";

        //System.out.println(QueryCAPEC);System.exit(0);
        Query qfQueryCAPEC = QueryFactory.create(QueryCAPEC);
        QueryExecution qeQueryCAPEC = QueryExecutionFactory.sparqlService(CyberKnowledgeEp, qfQueryCAPEC);
        //((QueryEngineHTTP)qeQueryCAPEC).addParam("timeout", "10000");
        ResultSet rsQueryCAPEC = qeQueryCAPEC.execSelect();

        //System.exit(0);
        ArrayList<String> CAPECResArray = new ArrayList<String>();
        ArrayList<String> CAPECIdArray = new ArrayList<String>();
        ArrayList<String>[] CAPECArrayOfList = new ArrayList[2];

        while (rsQueryCAPEC.hasNext()) {
            QuerySolution qsQueryCAPEC = rsQueryCAPEC.nextSolution();
            RDFNode CAPECRes = qsQueryCAPEC.get("s");
            RDFNode CAPECId = qsQueryCAPEC.get("id");
            CAPECResArray.add(CAPECRes.toString());
            CAPECIdArray.add(CAPECId.toString());

            //System.out.println(CAPECRes.toString());
        }
        //System.out.println(CAPECResArray);
        CAPECArrayOfList[0] = CAPECResArray;
        CAPECArrayOfList[1] = CAPECIdArray;

        //CAPECModel.close();
        // System.exit(0);
        return CAPECArrayOfList;
    }
}
