package ac.at.tuwien.ifs.sepses.linking;

import org.apache.jena.query.*;
import org.apache.jena.rdf.model.*;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

public class CWELinking {

    public static Model generateLinking(Model CWEModel, Model CAPECModel, String fileName) throws IOException {

        //load and read the rdf snort Rule

        //find the ac.at.tuwien.ifs.sepses.linking, if it exists generate ac.at.tuwien.ifs.sepses.linking otherwise make a log

        //query to get cveId property from snort alert
        String sidQuery = "select distinct ?capecId where {\r\n"
                + "    	?s a <http://sepses.ifs.tuwien.ac.at/vocab/ref/cwe#CWE>.\r\n"
                + "		?s <http://sepses.ifs.tuwien.ac.at/vocab/ref/cwe#capecId> ?capecId.\r\n" + "}";

        String sidQuery2 =
                "select ?s ?capecId where {\r\n" + "    	?s a <http://sepses.ifs.tuwien.ac.at/vocab/ref/cwe#CWE>.\r\n"
                        + "		?s <http://sepses.ifs.tuwien.ac.at/vocab/ref/cwe#capecId> ?capecId.\r\n" + "}";

        //generate filter for CVE query
        Query sidQ = QueryFactory.create(sidQuery);
        QueryExecution sidQex = QueryExecutionFactory.create(sidQ, CWEModel);
        ResultSet sidQResult = sidQex.execSelect();
        String filterStatement = "";
        while (sidQResult.hasNext()) {
            QuerySolution sidQS = sidQResult.nextSolution();
            // RDFNode snortRuleRes = sidQS.get("s");
            RDFNode CWECAPEC = sidQS.get("capecId");
            filterStatement = filterStatement + "?capecId = \"" + CWECAPEC + "\" || ";

        }

        System.out.println(filterStatement);
        System.exit(0);

        ArrayList<String>[] CAPECResArray =
                getCAPECResourceFilterStatement(filterStatement + "?capecId = \"0\"", CAPECModel);
        //System.out.println(CVEResArray);System.exit(0);

        Query sidQ2 = QueryFactory.create(sidQuery2);
        QueryExecution sidQex2 = QueryExecutionFactory.create(sidQ2, CWEModel);
        ResultSet sidQResult2 = sidQex2.execSelect();

        Model linkingModel = ModelFactory.createDefaultModel();
        Property hasCAPEC = linkingModel.createProperty("http://sepses.ifs.tuwien.ac.at/vocab/ref/cwe#hasCAPEC");
        Model NolinkingModel = ModelFactory.createDefaultModel();
        Property hasNoCAPEC = linkingModel.createProperty("http://sepses.ifs.tuwien.ac.at/vocab/ref/cwe#hasNoCAPEC");

        //String nolinking = "";
        int CAPECFound = 0;
        int CAPECNotFound = 0;
        while (sidQResult2.hasNext()) {
            QuerySolution sidQS2 = sidQResult2.nextSolution();
            RDFNode CWERes2 = sidQS2.get("s");
            RDFNode CWECAPEC2 = sidQS2.get("capecId");
            int CAPECfound = 0;
            int i = 0;
            while (CAPECResArray[1].size() > i) {

                // i++;
                if (CAPECResArray[1].get(i).equals(CWECAPEC2.toString().substring(4))) {
                    //System.out.print(CWEResArray[1].get(i)+"|");System.out.println(CVECWE4.toString().substring(4));
                    Resource resS = linkingModel.createResource(CWERes2.toString());
                    Resource resO = linkingModel.createResource(CAPECResArray[0].get(i));
                    resS.addProperty(hasCAPEC, resO);
                    CAPECfound++;
                    System.out.println(
                            "CAPEC Found, generate ac.at.tuwien.ifs.sepses.linking " + CWERes2.toString() + "to " + CAPECResArray[0].get(i));
                    // System.out.println(CWERes2.toString()+" "+lista);

                }
                i++;
                //  System.exit(0);
            }
            if (CAPECfound < 1) {
                Resource resSno = NolinkingModel.createResource(CWERes2.toString());
                resSno.addProperty(hasNoCAPEC, CWECAPEC2.toString());
                System.out.println(
                        "CAPEC Not Found, generate No ac.at.tuwien.ifs.sepses.linking " + CWERes2.toString() + "to " + CWECAPEC2.toString());
                CAPECNotFound++;
            } else {
                CAPECFound++;
            }

        }
        System.out.println("CAPEC Found :" + CAPECFound + ", CAPEC Not Found : " + CAPECNotFound);
        //System.exit(0);

        //linkingModel.write(System.out,"TURTLE");

        //String fileName = "output/ac.at.tuwien.ifs.sepses.linking/snortRuleToCVE.ttl";
        String fileNameNL = "output/ac.at.tuwien.ifs.sepses.linking/CWETOCAPEC_" + fileName + "_NoLinking.log.ttl";
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

    public static ArrayList<String>[] getCAPECResourceFilterStatement(String filterStatement, Model CAPECModel) {

        //query to get cveId property from snort rule
        String sidQuery = "select ?CAPECId ?s where {\r\n"
                + "    ?s a <http://sepses.ifs.tuwien.ac.at/vocab/ref/capec#CAPEC>.\r\n"
                + "    ?s <http://sepses.ifs.tuwien.ac.at/vocab/ref/capec#CAPECId> ?capecId .\r\n" + "    filter ("
                + filterStatement + ")\r\n" + "} \r\n";

        System.out.println(sidQuery);
        System.exit(0);

        Query sidQ = QueryFactory.create(sidQuery);
        QueryExecution sidQex = QueryExecutionFactory.create(sidQ, CAPECModel);
        ResultSet sidQResult = sidQex.execSelect();

        //System.exit(0);
        ArrayList<String> CAPECResArray = new ArrayList<String>();
        ArrayList<String> CAPECIdArray = new ArrayList<String>();
        ArrayList<String>[] CAPECArrayOfList = new ArrayList[2];

        while (sidQResult.hasNext()) {
            QuerySolution sidQS = sidQResult.nextSolution();
            RDFNode CAPECRes = sidQS.get("s");
            RDFNode CAPECId = sidQS.get("CAPECId");
            CAPECResArray.add(CAPECRes.toString());
            CAPECIdArray.add(CAPECId.toString());
            //System.out.println(CVERes.toString());
        }
        //System.out.println(CVEResArray);
        CAPECArrayOfList[0] = CAPECResArray;
        CAPECArrayOfList[1] = CAPECIdArray;
        CAPECModel.close();
        // System.exit(0);
        //return CAPECResArray;
        return CAPECArrayOfList;
    }

    //store additional generated ac.at.tuwien.ifs.sepses.linking triple to rdf snort alert

}
