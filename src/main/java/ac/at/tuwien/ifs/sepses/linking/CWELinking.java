package ac.at.tuwien.ifs.sepses.linking;

import org.apache.jena.query.*;
import org.apache.jena.rdf.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

public class CWELinking {

    private static final Logger log = LoggerFactory.getLogger(CWELinking.class);

    public static Model generateLinking(Model CWEModel, String CyberKnowledgeEp, String CAPECGraphName,
            String fileName, String outputDir) throws IOException {

        ArrayList<String>[] CAPECResArray = getAllCAPEC(CyberKnowledgeEp, CAPECGraphName);
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

            // for each subject result, select all CAPEC that the subject connect to
            String Query2 = "select ?capecId where {  \r\n"
                    + "?s <http://w3id.org/sepses/vocab/ref/cwe#capecId> ?capecId. \r\n" + "filter (?s = <" + CWEId
                    + ">) . \r\n" + "}";

            Query Q2 = QueryFactory.create(Query2);
            QueryExecution Qex2 = QueryExecutionFactory.create(Q2, CWEModel);
            ResultSet QResult2 = Qex2.execSelect();
            Property hasCAPEC = linkingModel.createProperty("http://w3id.org/sepses/vocab/ref/cwe#hasCAPEC");
            Property hasNoCAPEC = linkingModel.createProperty("http://w3id.org/sepses/vocab/ref/cwe#hasNoCAPEC");

            int capecGiven = 0;
            int capecFound = 0;
            int capecNotFound = 0;
            while (QResult2.hasNext()) {
                QuerySolution QS2 = QResult2.nextSolution();
                RDFNode capecId = QS2.get("?capecId");

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

            log.info("CWEID '" + CWEId + "' ** CAPEC Found :" + capecFound + ", CAPEC Not Found : " + capecNotFound
                    + ", CAPEC Given :" + capecGiven);
        }

        String fileNameNL = outputDir + "/update/linking/CWETOCAPEC_" + fileName + "_NoLinking.log.ttl";
        File f = new File(fileNameNL);
        f.getParentFile().mkdirs();
        FileWriter nolinkingCVECWELog = new FileWriter(f);

        try {
            NolinkingModel.write(nolinkingCVECWELog, "TURTLE");
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        return linkingModel;
    }

    public static ArrayList<String>[] getAllCAPEC(String CyberKnowledgeEp, String CAPECGraphName) {

        // Select all capecId and capec resource from CAPEC
        String QueryCAPEC = "select distinct ?s ?id from <" + CAPECGraphName + "> where {\r\n"
                + "    ?s a <http://w3id.org/sepses/vocab/ref/capec#CAPEC>.\r\n"
                + "    ?s <http://w3id.org/sepses/vocab/ref/capec#id> ?id .\r\n" + "  } ";

        Query qfQueryCAPEC = QueryFactory.create(QueryCAPEC);
        QueryExecution qeQueryCAPEC = QueryExecutionFactory.sparqlService(CyberKnowledgeEp, qfQueryCAPEC);
        ResultSet rsQueryCAPEC = qeQueryCAPEC.execSelect();

        ArrayList<String> CAPECResArray = new ArrayList<>();
        ArrayList<String> CAPECIdArray = new ArrayList<>();
        ArrayList<String>[] CAPECArrayOfList = new ArrayList[2];

        while (rsQueryCAPEC.hasNext()) {
            QuerySolution qsQueryCAPEC = rsQueryCAPEC.nextSolution();
            RDFNode CAPECRes = qsQueryCAPEC.get("s");
            RDFNode CAPECId = qsQueryCAPEC.get("id");
            CAPECResArray.add(CAPECRes.toString());
            CAPECIdArray.add(CAPECId.toString());
        }
        CAPECArrayOfList[0] = CAPECResArray;
        CAPECArrayOfList[1] = CAPECIdArray;

        return CAPECArrayOfList;
    }
}
