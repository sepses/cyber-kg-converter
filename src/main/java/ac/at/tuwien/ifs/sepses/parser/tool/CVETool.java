package ac.at.tuwien.ifs.sepses.parser.tool;

import ac.at.tuwien.ifs.sepses.vocab.CVE;
import org.apache.commons.io.IOUtils;
import org.apache.jena.query.*;
import org.apache.jena.rdf.model.*;
import org.apache.jena.update.UpdateExecutionFactory;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateProcessor;
import org.apache.jena.update.UpdateRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.Charset;
import java.util.ArrayList;

public class CVETool {

    private static final Logger log = LoggerFactory.getLogger(CVETool.class);

    public static ArrayList<String>[] checkExistingCVE(Model CVEModelTemp, String sparqlEndpoint, String CVEGraphName)
            throws IOException {

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
                    deleteCVE(sparqlEndpoint, cveRes.asResource(), CVEGraphName);
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

    /**
     * Delete older CVEs and replace them with the new version from incoming data
     *
     * @param endpoint    SPARQL endpoint
     * @param cveInstance CVE instance
     * @param graphName   named Graph
     * @throws IOException
     */
    private static void deleteCVE(String endpoint, Resource cveInstance, String graphName) throws IOException {
        InputStream is = CVETool.class.getClassLoader().getResourceAsStream("sparql/deleteCVE.sparql");
        String query = IOUtils.toString(is, Charset.defaultCharset());

        ParameterizedSparqlString deleteQuery = new ParameterizedSparqlString(query);
        deleteQuery.setParam("graph", ResourceFactory.createResource(graphName));
        deleteQuery.setParam("cve", cveInstance);
        deleteQuery.setNsPrefix("cve", CVE.NS);

        UpdateRequest updateRequest = UpdateFactory.create(deleteQuery.toString());
        UpdateProcessor updateProcessor = UpdateExecutionFactory.createRemote(updateRequest, endpoint);
        updateProcessor.execute();

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

    public static org.apache.jena.rdf.model.Model generateCVEMetaTriple(String metaSHA, int year) {
        org.apache.jena.rdf.model.Model CVEMetaModel = ModelFactory.createDefaultModel();
        Property metaSHA256 = CVEMetaModel.createProperty("http://w3id.org/sepses/vocab/ref/cve#metaSHA256");
        Resource CVEMeta1 = CVEMetaModel.createResource("http://w3id.org/sepses/resource/cve/meta/cveMeta" + year);
        CVEMetaModel.add(CVEMeta1, metaSHA256, metaSHA);
        return CVEMetaModel;

    }

    public static void deleteCVEMeta(String CyberKnowledgeEp, String Namegraph) {
        String p = "<http://w3id.org/sepses/vocab/ref/cve#metaSHA256>";
        String Query = "with  <" + Namegraph + "> DELETE { ?s ?p ?o }  WHERE { ?s ?p ?o.  filter (?p = " + p + ")}";
        UpdateRequest QCVE1 = UpdateFactory.create(Query);
        UpdateProcessor qeQCVE1 = UpdateExecutionFactory.createRemote(QCVE1, CyberKnowledgeEp);
        qeQCVE1.execute();
    }

}
