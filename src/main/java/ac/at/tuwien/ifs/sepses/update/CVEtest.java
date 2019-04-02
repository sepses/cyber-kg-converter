package ac.at.tuwien.ifs.sepses.update;

import org.apache.jena.query.*;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;

public class CVEtest {
    public static void main(String[] args) {
    }

    public static boolean checkSHAMeta(String SHA256, String CyberKnowledgeEp, String namegraph) {
        String Query = "select (count(?s) as ?c) from <" + namegraph + "> where {"
                + "?s <http://w3id.org/sepses/vocab/ref/cve#metaSHA256>  " + SHA256 + " }";
        //System.out.println(Query1);System.exit(0);
        Query qfQuery = QueryFactory.create(Query);
        QueryExecution qeQuery = QueryExecutionFactory.sparqlService(CyberKnowledgeEp, qfQuery);
        ResultSet rsQuery = qeQuery.execSelect();
        boolean found = false;
        while (rsQuery.hasNext()) {
            QuerySolution qsQuery = rsQuery.nextSolution();
            RDFNode c = qsQuery.get("c");
            if (!c.toString().equals("0^^http://www.w3.org/2001/XMLSchema#integer"))
                ;
            found = true;
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
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return metaSHA256;
    }

    public static org.apache.jena.rdf.model.Model generateCVEMetaTriple(String metaSHA) {
        org.apache.jena.rdf.model.Model CVEMetaModel = ModelFactory.createDefaultModel();
        Property metaSHA256 = CVEMetaModel.createProperty("http://w3id.org/sepses/vocab/ref/cve#metaSHA256");
        Resource CVEMeta1 = CVEMetaModel.createResource("http://w3id.org/sepses/resource/cve/meta/cveMeta1");
        CVEMetaModel.add(CVEMeta1, metaSHA256, metaSHA);
        //System.out.println(SHA256);
        return CVEMetaModel;

    }
}
