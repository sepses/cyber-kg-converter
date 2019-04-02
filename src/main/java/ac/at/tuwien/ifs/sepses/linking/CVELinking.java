package ac.at.tuwien.ifs.sepses.linking;

import org.apache.jena.query.*;
import org.apache.jena.rdf.model.*;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

public class CVELinking {

    public static Model generateLinking(Model CVEModel, Model CPEModel, Model CWEModel, String fileName)
            throws IOException {

        //load and read the rdf snort Rule

        //CVEModel.write(System.out,"TURTLE");System.exit(0);
        //find the ac.at.tuwien.ifs.sepses.linking, if it exists generate ac.at.tuwien.ifs.sepses.linking otherwise make a log

        //query to get cpeId property from CVE per year
        String sidQuery = "select distinct ?cpeId where { \r\n"
                + "?s <http://sepses.ifs.tuwien.ac.at/vocab/ref/cve#CPEId> ?cpeId .\r\n" + "} ";

        String sidQuery2 = "select ?s ?cpeId where { \r\n"
                + "    ?s <http://sepses.ifs.tuwien.ac.at/vocab/ref/cve#CPEId> ?cpeId .\r\n" + "}";

        //query to get cweId property from CVE per year
        String sidQuery3 = "select distinct ?cweId where { \r\n"
                + "    ?s <http://sepses.ifs.tuwien.ac.at/vocab/ref/cve#CWEId> ?cweId .\r\n" + "} \r\n" + "";

        String sidQuery4 = "select ?s ?cweId where { \r\n"
                + "    ?s <http://sepses.ifs.tuwien.ac.at/vocab/ref/cve#CWEId> ?cweId .\r\n" + "} \r\n" + "";

        //generate filter for CPE query
        Query sidQ = QueryFactory.create(sidQuery);
        QueryExecution sidQex = QueryExecutionFactory.create(sidQ, CVEModel);
        ResultSet sidQResult = sidQex.execSelect();
        String filterStatement = "";
        while (sidQResult.hasNext()) {
            QuerySolution sidQS = sidQResult.nextSolution();
            // RDFNode snortRuleRes = sidQS.get("s");
            RDFNode CVECPE = sidQS.get("cpeId");
            filterStatement = filterStatement + "?cpeId = \"" + CVECPE + "\" || ";

        }

        //System.out.println(filterStatement);System.exit(0);

        ArrayList<String> CPEResArray = getCPEResourceFilterStatement(filterStatement + "?cpeId = \"0\"", CPEModel);

        //generate filter for CWE query
        Query sidQ3 = QueryFactory.create(sidQuery3);
        QueryExecution sidQex3 = QueryExecutionFactory.create(sidQ3, CVEModel);
        ResultSet sidQResult3 = sidQex3.execSelect();
        String filterStatement2 = "";
        while (sidQResult3.hasNext()) {
            QuerySolution sidQS3 = sidQResult3.nextSolution();
            // RDFNode snortRuleRes = sidQS.get("s");
            RDFNode CVECWE = sidQS3.get("cweId");
            filterStatement2 = filterStatement2 + "?cweId = \"" + CVECWE + "\" || ";

        }
        System.out.println(filterStatement2);
        System.exit(0);

        ArrayList<String> CWEResArray = getCPEResourceFilterStatement(filterStatement2 + "?cweId = \"0\"", CWEModel);

        //System.out.println(CVEResArray);System.exit(0);

        // create ac.at.tuwien.ifs.sepses.linking CVE-CPE
        Query sidQ2 = QueryFactory.create(sidQuery2);
        QueryExecution sidQex2 = QueryExecutionFactory.create(sidQ2, CVEModel);
        ResultSet sidQResult2 = sidQex2.execSelect();

        //make new model for linking cpe result
        Model linkingModel = ModelFactory.createDefaultModel();
        Property hasCPE = linkingModel.createProperty("http://sepses.ifs.tuwien.ac.at/vocab/ref/cwe#hasCPE");
        String nolinking_cve_cpe = "";
        while (sidQResult2.hasNext()) {
            QuerySolution sidQS2 = sidQResult2.nextSolution();
            RDFNode CVERes2 = sidQS2.get("s");
            RDFNode CVECPE2 = sidQS2.get("cpeId");

            String lista = "http://example.org/sepses/cpe#" + CVECPE2.toString();
            // System.out.println(lista);

            if (CPEResArray.contains(lista)) {
                Resource resS = linkingModel.createResource(CVERes2.toString());
                Resource resO = linkingModel.createResource(lista);
                resS.addProperty(hasCPE, resO);
                // System.out.println(CWERes2.toString()+" "+lista);
            } else {
                nolinking_cve_cpe = CVERes2.toString() + ",cpeId:" + CVECPE2.toString() + "\n" + nolinking_cve_cpe;
                //System.out.println(CWECAPEC2.toString()+" has no ac.at.tuwien.ifs.sepses.linking !! ");
            }

        }
        //create ac.at.tuwien.ifs.sepses.linking CVE-CWE
        Query sidQ4 = QueryFactory.create(sidQuery2);
        QueryExecution sidQex4 = QueryExecutionFactory.create(sidQ4, CVEModel);
        ResultSet sidQResult4 = sidQex4.execSelect();

        //make new model for linking cpe result
        //Model linkingModel = ModelFactory.createDefaultModel();
        Property hasCWE = linkingModel.createProperty("http://sepses.ifs.tuwien.ac.at/vocab/ref/cwe#hasCWE");
        String nolinking_cve_cwe = "";
        while (sidQResult4.hasNext()) {
            QuerySolution sidQS4 = sidQResult4.nextSolution();
            RDFNode CVERes4 = sidQS4.get("s");
            RDFNode CVECWE4 = sidQS4.get("cweId");

            String lista = "http://example.org/sepses/cpe#" + CVECWE4.toString();
            // System.out.println(lista);

            if (CWEResArray.contains(lista)) {
                Resource resS = linkingModel.createResource(CVERes4.toString());
                Resource resO = linkingModel.createResource(lista);
                resS.addProperty(hasCWE, resO);
                // System.out.println(CWERes2.toString()+" "+lista);
            } else {
                nolinking_cve_cwe = CVERes4.toString() + ",cweId:" + CVECWE4.toString() + "\n" + nolinking_cve_cwe;
                //System.out.println(CWECAPEC2.toString()+" has no ac.at.tuwien.ifs.sepses.linking !! ");
            }

        }

        linkingModel.write(System.out, "TURTLE");

        //String fileName = "output/ac.at.tuwien.ifs.sepses.linking/snortRuleToCVE.ttl";
        String fileNameNL = "output/ac.at.tuwien.ifs.sepses.linking/CVETOCPE_" + fileName + "_NoLinking.log";
        String fileNameNL2 = "output/ac.at.tuwien.ifs.sepses.linking/CVETOCWE_" + fileName + "_NoLinking.log";
        // FileWriter rdfLinking = new FileWriter(fileName);
        FileWriter nolinkingCVECPELog = new FileWriter(fileNameNL);
        FileWriter nolinkingCVECWELog = new FileWriter(fileNameNL2);

        try {
            //	linkingModel.write(rdfLinking,"N3");
            nolinkingCVECPELog.write(nolinking_cve_cpe);
            nolinkingCVECWELog.write(nolinking_cve_cwe);
        } finally {
            linkingModel.close();
        }

        //CWEModel.close();

        return linkingModel;

    }

    public static ArrayList<String> getCPEResourceFilterStatement(String filterStatement, Model CPEModel) {

        //query to get cveId property from snort rule
        String sidQuery =
                "select ?cpeId ?s where {\r\n" + "    ?s a <http://sepses.ifs.tuwien.ac.at/vocab/ref/cpe#CPE>.\r\n"
                        + "    ?s <http://sepses.ifs.tuwien.ac.at/vocab/ref/cpe#cpeId> ?cpeId .\r\n" + "    filter ("
                        + filterStatement + ")\r\n" + "} \r\n";

        //System.out.println(sidQuery);System.exit(0);

        Query sidQ = QueryFactory.create(sidQuery);
        QueryExecution sidQex = QueryExecutionFactory.create(sidQ, CPEModel);
        ResultSet sidQResult = sidQex.execSelect();

        //System.exit(0);
        ArrayList<String> CPEResArray = new ArrayList<String>();

        while (sidQResult.hasNext()) {
            QuerySolution sidQS = sidQResult.nextSolution();
            RDFNode CPERes = sidQS.get("s");
            //RDFNode CPEId = sidQS.get("cpeId");
            CPEResArray.add(CPERes.toString());
            //System.out.println(CPERes.toString());
        }
        //System.out.println(CVEResArray);

        //CAPECModel.close();
        // System.exit(0);
        return CPEResArray;

    }

    public static ArrayList<String> getCWEResourceFilterStatement(String filterStatement, Model CWEModel) {

        //query to get cveId property from snort rule
        String sidQuery =
                "select ?cweId ?s where {\r\n" + "    ?s a <http://sepses.ifs.tuwien.ac.at/vocab/ref/cwe#CWE>.\r\n"
                        + "    ?s <http://sepses.ifs.tuwien.ac.at/vocab/ref/cwe#CWEId> ?cweId .\r\n" + "    filter ("
                        + filterStatement + ")\r\n" + "} \r\n";

        //System.out.println(sidQuery);System.exit(0);

        Query sidQ = QueryFactory.create(sidQuery);
        QueryExecution sidQex = QueryExecutionFactory.create(sidQ, CWEModel);
        ResultSet sidQResult = sidQex.execSelect();

        //System.exit(0);
        ArrayList<String> CWEResArray = new ArrayList<String>();

        while (sidQResult.hasNext()) {
            QuerySolution sidQS = sidQResult.nextSolution();
            RDFNode CWERes = sidQS.get("s");
            //RDFNode CPEId = sidQS.get("cpeId");
            CWEResArray.add(CWERes.toString());
            //System.out.println(CPERes.toString());
        }
        //System.out.println(CVEResArray);

        //CAPECModel.close();
        // System.exit(0);
        return CWEResArray;

    }

    //store additional generated ac.at.tuwien.ifs.sepses.linking triple to rdf snort alert

}
