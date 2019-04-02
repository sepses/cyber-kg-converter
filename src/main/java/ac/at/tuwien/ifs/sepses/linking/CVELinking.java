package ac.at.tuwien.ifs.sepses.linking;

import org.apache.jena.query.*;
import org.apache.jena.rdf.model.*;
import org.apache.jena.vocabulary.RDF;

import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

public class CVELinking {

    public static Model generateLinkingCVETOCPE(Model CVEModel, String CyberKnowledgeEp, String CPEGraphName,
            String fileName, String outputDir) throws IOException {

        //0. get All CPE data (cpeId and cpeResource to an array)
        ArrayList<String>[] CPEArrayofList = getAllCPE(CyberKnowledgeEp, CPEGraphName);

        //1. select all CVE subject
        String Query1 = "\r\n" + "select ?s where {\r\n" + "    ?s a <http://w3id.org/sepses/vocab/ref/cve#CVE> .\r\n"
                + "}\r\n" + "";
        //System.out.println(Query1);System.exit(0);

        Query Q1 = QueryFactory.create(Query1);
        QueryExecution Qex1 = QueryExecutionFactory.create(Q1, CVEModel);
        ResultSet QResult1 = Qex1.execSelect();
        Model linkingModelCVECPE = ModelFactory.createDefaultModel();
        Model NolinkingModelCVECPE = ModelFactory.createDefaultModel();
        ArrayList<String> foundCPE = new ArrayList<String>();
        ArrayList<String> foundCPERes = new ArrayList<String>();
        while (QResult1.hasNext()) {
            QuerySolution QS1 = QResult1.nextSolution();
            RDFNode cveId = QS1.get("?s");
            //System.out.println(cveId.toString());

            //generating CVE to CPE
            //2. for each subject result, select all CPE that the subject connect to
            String Query2 =
                    "select ?cpeId where {  \r\n" + "?s <http://w3id.org/sepses/vocab/ref/cve#cpeId> ?cpeId. \r\n"
                            + "filter (?s = <" + cveId + ">) . \r\n" + "}";

            //System.out.println(Query2);

            Query Q2 = QueryFactory.create(Query2);
            QueryExecution Qex2 = QueryExecutionFactory.create(Q2, CVEModel);
            ResultSet QResult2 = Qex2.execSelect();
            Property hasCPE = linkingModelCVECPE.createProperty("http://w3id.org/sepses/vocab/ref/cve#hasCPE");
            Property hasNoCPE = linkingModelCVECPE.createProperty("http://w3id.org/sepses/vocab/ref/cve#hasNoCPE");
            int cpeGiven = 0;
            int cpeFound = 0;
            int cpeNotFound = 0;
            while (QResult2.hasNext()) {
                QuerySolution QS2 = QResult2.nextSolution();
                RDFNode cpeId = QS2.get("?cpeId");
                // System.out.println(CPEArrayofList[1].size());
                //check in foundCPE array
                if (foundCPE.contains(cpeId.toString())) {
                    // System.out.println("found in local!");
                    int keyFoundCPE = foundCPE.indexOf(cpeId.toString());
                    Resource resS = linkingModelCVECPE.createResource(cveId.toString());
                    Resource resO = linkingModelCVECPE.createResource(foundCPERes.get(keyFoundCPE));
                    resS.addProperty(hasCPE, resO);
                    cpeFound++;
                    //if not
                } else {
                    //check in CPEArrayOfList
                    if (CPEArrayofList[1].contains(cpeId.toString())) {
                        //System.out.println("found in endpoint!");

                        int key = CPEArrayofList[1].indexOf(cpeId.toString());
                        //save found cpe
                        foundCPE.add(CPEArrayofList[1].get(key));
                        foundCPERes.add(CPEArrayofList[0].get(key));
                        //System.out.println("CPE found in local= "+foundCPE.size());
                        Resource resS = linkingModelCVECPE.createResource(cveId.toString());
                        Resource resO = linkingModelCVECPE.createResource(CPEArrayofList[0].get(key));
                        resS.addProperty(hasCPE, resO);
                        cpeFound++;
                    } else {
                        Resource resSn = NolinkingModelCVECPE.createResource(cveId.toString());
                        resSn.addProperty(hasNoCPE, cpeId);
                        cpeNotFound++;
                    }
                }
                cpeGiven++;
            }
            //end of generating CVE to CPE
            //generating CVE to Vulnerability Configuration
            //2. for each subject result, select all CPE that the subject connect to
            String Query3 = "select distinct  ?vc ?fr ?op ?n where {\r\n"
                    + "    ?s a <http://w3id.org/sepses/vocab/ref/cve#CVE>.\r\n"
                    + "    ?s <http://w3id.org/sepses/vocab/ref/cve#hasVulnerableConfiguration> ?vc.\r\n"
                    + "    ?vc <http://w3id.org/sepses/vocab/ref/cpe#logicalTestFactRef> ?fr.\r\n"
                    + "    ?vc <http://w3id.org/sepses/vocab/ref/cpe#logicalTestOperator> ?op.\r\n"
                    + "	 ?vc <http://w3id.org/sepses/vocab/ref/cpe#logicalTestNegate> ?n.\r\n" + "filter (?s = <"
                    + cveId + ">) . \r\n" + "}";

            // System.out.println(Query3);System.exit(0);

            Query Q3 = QueryFactory.create(Query3);
            QueryExecution Qex3 = QueryExecutionFactory.create(Q3, CVEModel);
            ResultSet QResult3 = Qex3.execSelect();
            Property hasLogicalTestFactRef =
                    linkingModelCVECPE.createProperty("http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTestFactRef");
            Property hasLogicalTest =
                    linkingModelCVECPE.createProperty("http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTest");
            Property logicalTestOperator =
                    linkingModelCVECPE.createProperty("http://w3id.org/sepses/vocab/ref/cpe#logicalTestOperator");
            Property logicalTestNegate =
                    linkingModelCVECPE.createProperty("http://w3id.org/sepses/vocab/ref/cpe#logicalTestNegate");
            Property hasVulnerableConfiguration = linkingModelCVECPE
                    .createProperty("http://w3id.org/sepses/vocab/ref/cve#hasVulnerableConfiguration");
            Property hasNoLogicalTestFactRef =
                    linkingModelCVECPE.createProperty("http://w3id.org/sepses/vocab/ref/cpe#hasNoLogicalTestFactRef");
            int frGiven = 0;
            int frFound = 0;
            int frNotFound = 0;
            while (QResult3.hasNext()) {
                QuerySolution QS3 = QResult3.nextSolution();
                RDFNode cpeId = QS3.get("?fr");
                RDFNode vc = QS3.get("?vc");
                RDFNode op = QS3.get("?op");
                RDFNode n = QS3.get("?n");
                // System.out.println(CPEArrayofList[1].size());
                //check in foundCPE array
                if (foundCPE.contains(cpeId.toString())) {
                    // System.out.println("found in local!");
                    int keyFoundCPE = foundCPE.indexOf(cpeId.toString());
                    Resource resCVE = linkingModelCVECPE.createResource(cveId.toString());
                    Resource resS = linkingModelCVECPE.createResource(vc.toString());

                    Resource resO = linkingModelCVECPE.createResource(foundCPERes.get(keyFoundCPE));
                    Resource LogicalTest =
                            linkingModelCVECPE.createResource("http://w3id.org/sepses/vocab/ref/cpe#LogicalTest");
                    resCVE.addProperty(hasVulnerableConfiguration, resS);
                    resS.addProperty(hasLogicalTestFactRef, resO);
                    resS.addProperty(logicalTestOperator, op.toString());
                    resS.addProperty(logicalTestNegate, n.toString());
                    resS.addProperty(RDF.type, LogicalTest);
                    frFound++;
                    //if not
                } else {
                    //check in CPEArrayOfList
                    if (CPEArrayofList[1].contains(cpeId.toString())) {
                        //System.out.println("found in endpoint!");

                        int key = CPEArrayofList[1].indexOf(cpeId.toString());
                        //save found cpe
                        foundCPE.add(CPEArrayofList[1].get(key));
                        foundCPERes.add(CPEArrayofList[0].get(key));
                        //System.out.println("CPE found in local= "+foundCPE.size());
                        Resource resCVE = linkingModelCVECPE.createResource(cveId.toString());
                        Resource resS = linkingModelCVECPE.createResource(vc.toString());
                        Resource resO = linkingModelCVECPE.createResource(CPEArrayofList[0].get(key));
                        Resource LogicalTest =
                                linkingModelCVECPE.createResource("http://w3id.org/sepses/vocab/ref/cpe#LogicalTest");
                        resCVE.addProperty(hasVulnerableConfiguration, resS);

                        resS.addProperty(hasLogicalTestFactRef, resO);
                        resS.addProperty(logicalTestOperator, op.toString());
                        resS.addProperty(logicalTestNegate, n.toString());
                        resS.addProperty(RDF.type, LogicalTest);
                        frFound++;
                    } else {
                        Resource resCVE = NolinkingModelCVECPE.createResource(cveId.toString());
                        Resource resSn = NolinkingModelCVECPE.createResource(vc.toString());
                        Resource LogicalTestN = NolinkingModelCVECPE
                                .createResource("http://w3id.org/sepses/vocab/ref/cpe#LogicalTest");
                        resCVE.addProperty(hasVulnerableConfiguration, resSn);
                        resSn.addProperty(hasNoLogicalTestFactRef, cpeId);
                        resSn.addProperty(logicalTestOperator, op.toString());
                        resSn.addProperty(logicalTestNegate, n.toString());
                        resSn.addProperty(RDF.type, LogicalTestN);
                        frNotFound++;
                    }
                }
                frGiven++;
            }

            //end of generating CPE to vulnConfiguration
            //generating Vulnerability Configuration to logicalTest
            //2. for each subject result, select all CPE that the subject connect to
            String Query4 = "select distinct  ?vc ?op1 ?n1 ?lt ?fr ?op ?n where {\r\n"
                    + "    ?s a <http://w3id.org/sepses/vocab/ref/cve#CVE>.\r\n"
                    + "    ?s <http://w3id.org/sepses/vocab/ref/cve#hasVulnerableConfiguration> ?vc.\r\n"
                    + "	 ?vc <http://w3id.org/sepses/vocab/ref/cpe#logicalTestOperator> ?op1.\r\n"
                    + "	 ?vc <http://w3id.org/sepses/vocab/ref/cpe#logicalTestNegate> ?n1.\r\n"
                    + "    ?vc <http://w3id.org/sepses/vocab/ref/cpe#hasLogicalTest> ?lt.\r\n"
                    + "    ?lt <http://w3id.org/sepses/vocab/ref/cpe#logicalTestFactRef> ?fr.\r\n"
                    + "    ?lt <http://w3id.org/sepses/vocab/ref/cpe#logicalTestOperator> ?op.\r\n"
                    + "	 ?lt <http://w3id.org/sepses/vocab/ref/cpe#logicalTestNegate> ?n.\r\n" + "filter (?s = <"
                    + cveId + ">) . \r\n" + "}";

            // System.out.println(Query4);System.exit(0);

            Query Q4 = QueryFactory.create(Query4);
            QueryExecution Qex4 = QueryExecutionFactory.create(Q4, CVEModel);
            ResultSet QResult4 = Qex4.execSelect();
            int fr2Given = 0;
            int fr2Found = 0;
            int fr2NotFound = 0;
            while (QResult4.hasNext()) {
                QuerySolution QS4 = QResult4.nextSolution();
                RDFNode cpeId = QS4.get("?fr");
                RDFNode vc = QS4.get("?vc");
                RDFNode op1 = QS4.get("?op1");
                RDFNode n1 = QS4.get("?n1");
                RDFNode lt = QS4.get("?lt");
                RDFNode op = QS4.get("?op");
                RDFNode n = QS4.get("?n");
                // System.out.println(CPEArrayofList[1].size());
                //check in foundCPE array
                if (foundCPE.contains(cpeId.toString())) {
                    // System.out.println("found in local!");
                    int keyFoundCPE = foundCPE.indexOf(cpeId.toString());
                    Resource resCVE = linkingModelCVECPE.createResource(cveId.toString());
                    Resource resSv = linkingModelCVECPE.createResource(vc.toString());
                    Resource resS = linkingModelCVECPE.createResource(lt.toString());
                    Resource resO = linkingModelCVECPE.createResource(foundCPERes.get(keyFoundCPE));
                    Resource LogicalTest =
                            linkingModelCVECPE.createResource("http://w3id.org/sepses/vocab/ref/cpe#LogicalTest");
                    resCVE.addProperty(hasVulnerableConfiguration, resSv);
                    resSv.addProperty(hasLogicalTest, resS);
                    resSv.addProperty(logicalTestOperator, op1.toString());
                    resSv.addProperty(logicalTestNegate, n1.toString());
                    resSv.addProperty(RDF.type, LogicalTest);
                    resS.addProperty(hasLogicalTestFactRef, resO);
                    resS.addProperty(logicalTestOperator, op.toString());
                    resS.addProperty(logicalTestNegate, n.toString());
                    resS.addProperty(RDF.type, LogicalTest);
                    fr2Found++;
                    //if not
                } else {
                    //check in CPEArrayOfList
                    if (CPEArrayofList[1].contains(cpeId.toString())) {
                        //System.out.println("found in endpoint!");
                        int key = CPEArrayofList[1].indexOf(cpeId.toString());
                        //save found cpe
                        foundCPE.add(CPEArrayofList[1].get(key));
                        foundCPERes.add(CPEArrayofList[0].get(key));
                        //System.out.println("CPE found in local= "+foundCPE.size());
                        Resource resCVE = linkingModelCVECPE.createResource(cveId.toString());
                        Resource resSv = linkingModelCVECPE.createResource(vc.toString());
                        Resource resS = linkingModelCVECPE.createResource(lt.toString());
                        Resource resO = linkingModelCVECPE.createResource(CPEArrayofList[0].get(key));
                        Resource LogicalTest =
                                linkingModelCVECPE.createResource("http://w3id.org/sepses/vocab/ref/cpe#LogicalTest");
                        resCVE.addProperty(hasVulnerableConfiguration, resSv);
                        resSv.addProperty(hasLogicalTest, resS);
                        resSv.addProperty(logicalTestOperator, op1.toString());
                        resSv.addProperty(logicalTestNegate, n1.toString());
                        resSv.addProperty(RDF.type, LogicalTest);
                        resS.addProperty(hasLogicalTestFactRef, resO);
                        resS.addProperty(logicalTestOperator, op.toString());
                        resS.addProperty(logicalTestNegate, n.toString());
                        resS.addProperty(RDF.type, LogicalTest);

                        fr2Found++;
                    } else {
                        Resource resCVE = NolinkingModelCVECPE.createResource(cveId.toString());
                        Resource resSvn = NolinkingModelCVECPE.createResource(vc.toString());
                        Resource resSn = NolinkingModelCVECPE.createResource(lt.toString());
                        Resource LogicalTestN = NolinkingModelCVECPE
                                .createResource("http://w3id.org/sepses/vocab/ref/cpe#LogicalTest");
                        resCVE.addProperty(hasVulnerableConfiguration, resSn);
                        resSvn.addProperty(hasLogicalTest, resSn);
                        resSvn.addProperty(logicalTestOperator, op1.toString());
                        resSvn.addProperty(logicalTestNegate, n1.toString());
                        resSvn.addProperty(RDF.type, LogicalTestN);
                        resSn.addProperty(hasNoLogicalTestFactRef, cpeId);
                        resSn.addProperty(logicalTestOperator, op.toString());
                        resSn.addProperty(logicalTestNegate, n.toString());
                        resSn.addProperty(RDF.type, LogicalTestN);
                        fr2NotFound++;
                    }
                }
                fr2Given++;
            }

            //end of generating CPE to vulnConfiguration

            System.out.println(cveId + " CPE found= " + cpeFound + " & CPE Not Found=" + cpeNotFound + " , given CPE="
                    + (cpeGiven));
            System.out.println(
                    cveId + " CPEfr found= " + frFound + " & CPEfr Not Found=" + frNotFound + " , given CPEfr="
                            + (frGiven));
            System.out.println(
                    cveId + " CPEfr2 found= " + fr2Found + " & Ffr2 Not Found=" + fr2NotFound + " ,given CPEfr2="
                            + (fr2Given));

        }
        System.out.println("Total CPE found and saved in memory= " + foundCPE.size());

        String currentDate = new SimpleDateFormat("yyyyMMddHHmm").format(new Date());
        String fileNameNL = outputDir + "/ac/at/tuwien/ifs/sepses/linking/CVETOCPE_" + fileName + currentDate
                + "_NoLinking.log.ttl";
        // FileWriter rdfLinking = new FileWriter(fileName);
        FileWriter nolinkingCVECPELog = new FileWriter(fileNameNL);

        try {

            //nolinkingCVECPELog.write(nolinking_cve_cpe);
            NolinkingModelCVECPE.write(nolinkingCVECPELog, "TURTLE");
        } finally {
            //linkingModel.close();

        }

        // System.exit(0);

        return linkingModelCVECPE;
    }

    public static Model generateLinkingCVETOCWE(Model CVEModel, String CyberKnowledgeEp, String CWEGraphName,
            String fileName, String outputDir) throws IOException {

        //load and read the rdf snort Rule

        //CVEModel.write(System.out,"TURTLE");System.exit(0);
        //find the ac.at.tuwien.ifs.sepses.linking, if it exists generate ac.at.tuwien.ifs.sepses.linking otherwise make a log
        ArrayList<String>[] CWEArrayofList = getAllCWE(CyberKnowledgeEp, CWEGraphName);
        //System.out.print(CWEArrayofList[1].size());	System.exit(0);
        //query to get cweId property from CVE per year

        String CWEQuery =
                "select ?s ?cweId where { \r\n" + "    ?s <http://w3id.org/sepses/vocab/ref/cve#cweId> ?cweId .\r\n"
                        + "} \r\n" + "";

        Query qfCWEQuery = QueryFactory.create(CWEQuery);
        QueryExecution qeCWEQuery = QueryExecutionFactory.create(qfCWEQuery, CVEModel);
        ResultSet rsCWEQuery = qeCWEQuery.execSelect();

        //make new model for linking cpe result
        Model linkingModel = ModelFactory.createDefaultModel();
        Model NolinkingModel = ModelFactory.createDefaultModel();
        Property hasCWE = linkingModel.createProperty("http://w3id.org/sepses/vocab/ref/cwe#hasCWE");
        Property hasNoCWE = linkingModel.createProperty("http://w3id.org/sepses/vocab/ref/cwe#hasNoCWE");
        //  String nolinking_cve_cwe = "";
        int cweFound = 0;
        int cweNotFound = 0;
        int cweGiven = 0;
        ArrayList<String> foundCWE = new ArrayList<String>();
        ArrayList<String> foundCWERes = new ArrayList<String>();
        while (rsCWEQuery.hasNext()) {
            QuerySolution qsCWEQuery = rsCWEQuery.nextSolution();
            RDFNode cveId = qsCWEQuery.get("s");
            RDFNode cweId = qsCWEQuery.get("cweId");
            //System.out.println(cveId.toString().substring(4));
            // System.out.println(cweId.toString());
            //check in foundCPE array
            if (foundCWE.contains(cweId.toString().substring(4))) {
                // System.out.println("found in local!");
                int keyFoundCWE = foundCWE.indexOf(cweId.toString().substring(4));
                Resource resS = linkingModel.createResource(cveId.toString());
                Resource resO = linkingModel.createResource(foundCWERes.get(keyFoundCWE));
                resS.addProperty(hasCWE, resO);
                cweFound++;
                System.out.println(cveId + ", CWE Found !");
                //if not
            } else {
                //check in CPEArrayOfList
                if (CWEArrayofList[1].contains(cweId.toString().substring(4))) {
                    //System.out.println("found in endpoint!");

                    int key = CWEArrayofList[1].indexOf(cweId.toString().substring(4));
                    //save found cwe
                    foundCWE.add(CWEArrayofList[1].get(key));
                    foundCWERes.add(CWEArrayofList[0].get(key));
                    //System.out.println("CWE found in local= "+foundCWE.size());
                    Resource resS = linkingModel.createResource(cveId.toString());
                    Resource resO = linkingModel.createResource(CWEArrayofList[0].get(key));
                    resS.addProperty(hasCWE, resO);
                    cweFound++;
                    System.out.println(cveId + ", CWE Found !");
                } else {
                    Resource resSn = NolinkingModel.createResource(cveId.toString());
                    resSn.addProperty(hasNoCWE, cweId);
                    cweNotFound++;
                    System.out.print(cveId + ", CWE Not Found!");
                    System.out.println(cweId);
                }
            }
            cweGiven++;
        }
        System.out.println("CWE Found :" + cweFound + ", CWE Not Found : " + cweNotFound + " Given CWE:" + cweGiven);
        //System.exit(0);

        //linkingModel.write(System.out,"TURTLE");
        String currentDate = new SimpleDateFormat("yyyyMMddHHmm").format(new Date());
        //String fileName = "output/ac.at.tuwien.ifs.sepses.linking/snortRuleToCVE.ttl";
        String fileNameNL = outputDir + "/ac/at/tuwien/ifs/sepses/linking/CVETOCWE_" + fileName + currentDate
                + "_NoLinking.log.ttl";
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

    public static ArrayList<String>[] getAllCWE(String CyberKnowledgeEp, String CWEGraphName) {

        //query to get cveId property from snort rule
        String sidQuery = "select distinct ?cweId ?s from <" + CWEGraphName + "> where {\r\n"
                + "    ?s a <http://w3id.org/sepses/vocab/ref/cwe#CWE>.\r\n"
                + "    ?s <http://w3id.org/sepses/vocab/ref/cwe#id> ?cweId .\r\n" + "} \r\n";

        //	System.out.println(sidQuery);System.exit(0);

        Query sidQ = QueryFactory.create(sidQuery);
        QueryExecution sidQex = QueryExecutionFactory.sparqlService(CyberKnowledgeEp, sidQ);
        // ((QueryEngineHTTP)sidQex).addParam("timeout", "10000");
        ResultSet sidQResult = sidQex.execSelect();

        //System.exit(0);
        ArrayList<String> CWEResArray = new ArrayList<String>();
        ArrayList<String> CWEIdArray = new ArrayList<String>();
        ArrayList<String>[] CWEArrayOfList = new ArrayList[2];

        while (sidQResult.hasNext()) {
            QuerySolution sidQS = sidQResult.nextSolution();
            RDFNode CWERes = sidQS.get("s");
            RDFNode CWEId = sidQS.get("cweId");
            CWEResArray.add(CWERes.toString());
            CWEIdArray.add(CWEId.toString());

            //System.out.println(CPERes.toString());
        }
        //System.out.println(CVEResArray);
        CWEArrayOfList[0] = CWEResArray;
        CWEArrayOfList[1] = CWEIdArray;

        //CAPECModel.close();
        // System.exit(0);
        return CWEArrayOfList;

    }

    public static ArrayList<String>[] getAllCPE(String CyberKnowledgeEp, String CPEGraphName) {

        //0. Select all cpeId and cpe resource from CPE
        String QueryCPE = "select distinct ?s ?cpeId from <" + CPEGraphName + "> where {\r\n"
                + "    ?s a <http://w3id.org/sepses/vocab/ref/cpe#CPE>.\r\n"
                + "    ?s <http://w3id.org/sepses/vocab/ref/cpe#id> ?cpeId .\r\n" + "  } ";

        Query qfQueryCPE = QueryFactory.create(QueryCPE);
        QueryExecution qeQueryCPE = QueryExecutionFactory.sparqlService(CyberKnowledgeEp, qfQueryCPE);
        //((QueryEngineHTTP)qeQueryCPE).addParam("timeout", "10000");
        ResultSet rsQueryCPE = qeQueryCPE.execSelect();

        //System.exit(0);
        ArrayList<String> CPEResArray = new ArrayList<String>();
        ArrayList<String> CPEIdArray = new ArrayList<String>();
        ArrayList<String>[] CPEArrayOfList = new ArrayList[2];

        while (rsQueryCPE.hasNext()) {
            QuerySolution qsQueryCPE = rsQueryCPE.nextSolution();
            RDFNode CPERes = qsQueryCPE.get("s");
            RDFNode CPEId = qsQueryCPE.get("cpeId");
            CPEResArray.add(CPERes.toString());
            CPEIdArray.add(CPEId.toString());

            //System.out.println(CPERes.toString());
        }
        //System.out.println(CVEResArray);
        CPEArrayOfList[0] = CPEResArray;
        CPEArrayOfList[1] = CPEIdArray;

        //CAPECModel.close();
        // System.exit(0);
        return CPEArrayOfList;
    }

    //store additional generated ac.at.tuwien.ifs.sepses.linking triple to rdf snort alert

}
