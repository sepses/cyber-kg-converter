package ac.at.tuwien.ifs.sepses.processor.updater;

import org.apache.jena.query.*;
import org.apache.jena.rdf.model.*;
import org.apache.jena.update.UpdateExecutionFactory;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateProcessor;
import org.apache.jena.update.UpdateRequest;

import java.util.ArrayList;

public class CPEUpdate {

    public static String checkExistingTriple(String CyberKnowledgeEp, String CPEGraphName) {
        //select if resource is not empty
        String Query1 = "select (str(count(?s)) as ?c) from <" + CPEGraphName + "> where {\r\n"
                + "?s a <http://w3id.org/sepses/vocab/ref/cpe#CPE>\r\n" + "}";
        //System.out.println(Query1);System.exit(0);
        Query qfQuery1 = QueryFactory.create(Query1);
        QueryExecution qeQuery1 = QueryExecutionFactory.sparqlService(CyberKnowledgeEp, qfQuery1);
        ResultSet rsQuery1 = qeQuery1.execSelect();
        String c = "";
        while (rsQuery1.hasNext()) {
            QuerySolution qsQueryCPE = rsQuery1.nextSolution();
            RDFNode cpe = qsQueryCPE.get("c");
            c = cpe.toString();
        }
        return c;

    }

    public static String countCPE(Model CPEModel) {
        //select if resource is not empty
        String Query1 =
                "select (str(count(?s)) as ?c) where {\r\n" + "?s a <http://w3id.org/sepses/vocab/ref/cpe#CPE>\r\n"
                        + "}";
        //System.out.println(Query1);System.exit(0);
        Query qfQuery1 = QueryFactory.create(Query1);
        QueryExecution qeQuery1 = QueryExecutionFactory.create(qfQuery1, CPEModel);
        ResultSet rsQuery1 = qeQuery1.execSelect();
        String c = "";
        while (rsQuery1.hasNext()) {
            QuerySolution qsQueryCPE = rsQuery1.nextSolution();
            RDFNode cpe = qsQueryCPE.get("c");
            c = cpe.toString();
        }
        return c;

    }

    public static boolean checkingCPEVersion(Model CPEModelTemp, String CyberKnowledgeEp, String CPEGraphName) {

        //query to cyberknowledge
        String Query1 = "select ?t from <" + CPEGraphName + "> where {"
                + "?s <http://w3id.org/sepses/vocab/ref/cpe#generatorTimeStamp>  ?t }";
        //System.out.println(Query1);//System.exit(0);
        Query qfQuery1 = QueryFactory.create(Query1);
        QueryExecution qeQuery1 = QueryExecutionFactory.sparqlService(CyberKnowledgeEp, qfQuery1);
        ResultSet rsQuery1 = qeQuery1.execSelect();
        String timestamp1 = "";
        while (rsQuery1.hasNext()) {
            QuerySolution qsQuery1 = rsQuery1.nextSolution();
            RDFNode t1 = qsQuery1.get("t");
            timestamp1 = t1.toString();
        }

        //select cpe model
        String Query2 = "select ?t where {" + "?s <http://w3id.org/sepses/vocab/ref/cpe#generatorTimeStamp>  ?t }";
        //System.out.println(Query2);System.exit(0);

        Query qfQuery2 = QueryFactory.create(Query2);
        QueryExecution qeQuery2 = QueryExecutionFactory.create(qfQuery2, CPEModelTemp);
        ResultSet rsQuery2 = qeQuery2.execSelect();
        String timestamp2 = "test";
        while (rsQuery2.hasNext()) {
            QuerySolution qsQuery2 = rsQuery2.nextSolution();
            RDFNode t2 = qsQuery2.get("t");
            timestamp2 = t2.toString();
        }
        if (timestamp1 == "") {
            timestamp1 = "Unknown!";
        }
        System.out.println("Existing CPE Update: " + timestamp1);
        System.out.println("Incoming CPE Update: " + timestamp2);

        if (timestamp1.equals(timestamp2)) {
            return true;
        } else {
            return false;
        }
    }

    public static Model generateAdditionalCPE(Model cPEModel, String cyberKnowledgeEp, String cPEGraphName) {
        //select cpe from cyberknowledge -> save to an array
        String Query1 =
                "select ?s  from <" + cPEGraphName + "> where {" + "?s a <http://w3id.org/sepses/vocab/ref/cpe#CPE>."
                        + "}";
        Query qfQuery1 = QueryFactory.create(Query1);
        QueryExecution qeQuery1 = QueryExecutionFactory.sparqlService(cyberKnowledgeEp, qfQuery1);
        ResultSet rsQuery1 = qeQuery1.execSelect();
        ArrayList<String> CPEArray = new ArrayList<String>();
        while (rsQuery1.hasNext()) {
            QuerySolution qsQueryCPE = rsQuery1.nextSolution();
            RDFNode cpe = qsQueryCPE.get("s");
            CPEArray.add(cpe.toString());
        }
        //System.out.println("jumlah cpe triple store ="+CPEArray.size());
        //create temporary model for additional cpe => tempCPEModel
        Model tempCPEModel = null;
        //select cpe from cpe model, for each cpe:
        String Query2 = "select ?s where {" + "?s a <http://w3id.org/sepses/vocab/ref/cpe#CPE>." + " }";
        Query qfQuery2 = QueryFactory.create(Query2);
        QueryExecution qeQuery2 = QueryExecutionFactory.create(qfQuery2, cPEModel);
        ResultSet rsQuery2 = qeQuery2.execSelect();
        int i = 0;
        int i2 = 0;
        while (rsQuery2.hasNext()) {
            QuerySolution qsQueryCPE2 = rsQuery2.nextSolution();
            RDFNode cpe2 = qsQueryCPE2.get("s");
            //check if cpe in cpe model exists in cpe cyberknowledge, if not:
            if (!CPEArray.contains(cpe2.toString())) {
                //create (construct) triple and add cpe to tempCPEModel
                //constructCPE(cpe2)
                System.out.println(cpe2);
                i++;
            }

            //join to tempCPEModel;

            i2++;
            //log the new CPE
        }

        System.out.println("New CPE=" + i);
        System.out.println("All CPE=" + i2);
        //System.exit(0);
        //return tempCPEModel
        return tempCPEModel;

    }

    public static void updateCPE(Model cPEModel, String cyberKnowledgeEp, String cPEGraphName) {
        // TODO Auto-generated method stub

    }

    public static void deleteGenerator(String cyberKnowledgeEp, String cPEGraphName) {
        // TODO Auto-generated method stub
        String deleteQuery = "with <" + cPEGraphName + "> DELETE { ?s ?p ?o }  \r\n" + "WHERE { ?s ?p ?o. "
                + "?s a <http://w3id.org/sepses/vocab/ref/cpe#Generator>." + "}";
        // System.out.println(deleteQuery);
        // System.exit(0);
        UpdateRequest QCPE = UpdateFactory.create(deleteQuery);
        UpdateProcessor qeQCPE = UpdateExecutionFactory.createRemote(QCPE, cyberKnowledgeEp);
        qeQCPE.execute();
    }

    public static Model generateAdditionalTriples(Model CPEModel) {
        //query to cpeModel
        Model addCPEModel = ModelFactory.createDefaultModel();
        String prefix = "http://w3id.org/sepses/vocab/ref/cpe#";
        Property cpe_version = addCPEModel.createProperty(prefix + "cpe_version");
        Property part = addCPEModel.createProperty(prefix + "part");
        Property version = addCPEModel.createProperty(prefix + "version");
        Property update = addCPEModel.createProperty(prefix + "ac/at/tuwien/ifs/sepses/processor");
        Property edition = addCPEModel.createProperty(prefix + "edition");
        Property language = addCPEModel.createProperty(prefix + "language");
        Property softwareEdition = addCPEModel.createProperty(prefix + "softwareEdition");
        Property targetSoftware = addCPEModel.createProperty(prefix + "targetSoftware");
        Property targetHardware = addCPEModel.createProperty(prefix + "targetHardware");
        Property other = addCPEModel.createProperty(prefix + "other");

        String Query1 = "select ?s ?cpe23 where {" + "?s <http://w3id.org/sepses/vocab/ref/cpe#cpe23>  ?cpe23 }";
        //System.out.println(Query1);System.exit(0);
        Query qfQuery1 = QueryFactory.create(Query1);
        QueryExecution qeQuery1 = QueryExecutionFactory.create(qfQuery1, CPEModel);
        ResultSet rsQuery1 = qeQuery1.execSelect();

        while (rsQuery1.hasNext()) {
            QuerySolution qsQuery1 = rsQuery1.nextSolution();
            RDFNode s = qsQuery1.get("?s");
            RDFNode cpe23 = qsQuery1.get("?cpe23");
            String cpe23s = cpe23.toString();
            Resource resS = addCPEModel.createResource(s.toString());

            String cpe1 = cpe23s.substring(0, cpe23s.indexOf(":"));
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

            resS.addProperty(cpe_version, cpe2);
            resS.addProperty(part, cpe3);
            resS.addProperty(version, cpe6);
            resS.addProperty(update, cpe7);
            resS.addProperty(edition, cpe8);
            resS.addProperty(language, cpe9);
            resS.addProperty(softwareEdition, cpe10);
            resS.addProperty(targetSoftware, cpe11);
            resS.addProperty(targetHardware, cpe10);
            resS.addProperty(other, cpe12);
        }
        return addCPEModel;
    }

    private void parseAllCVE() {

    }

}
