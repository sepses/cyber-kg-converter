package ac.at.tuwien.ifs.sepses.parser.tool;

import ac.at.tuwien.ifs.sepses.vocab.CPE;
import org.apache.jena.query.*;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CPETool {

    private static final Logger log = LoggerFactory.getLogger(CPETool.class);

    /**
     * Since RML load everyting into memory, we unload some of its tasks in this function, to reduce processing time.
     *
     * @param CPEModel
     * @return additional triples for CPE model
     */
    public static Model generateAdditionalTriples(Model CPEModel) {

        //query to cpeModel
        Model additionalCPEModel = ModelFactory.createDefaultModel();

        String Query1 = "select ?s ?cpe23 where {" + "?s <http://w3id.org/sepses/vocab/ref/cpe#cpe23>  ?cpe23 }";
        Query qfQuery1 = QueryFactory.create(Query1);
        QueryExecution qeQuery1 = QueryExecutionFactory.create(qfQuery1, CPEModel);
        ResultSet rsQuery1 = qeQuery1.execSelect();

        while (rsQuery1.hasNext()) {
            QuerySolution qsQuery1 = rsQuery1.nextSolution();
            RDFNode s = qsQuery1.get("?s");
            RDFNode cpe23 = qsQuery1.get("?cpe23");
            String cpe23s = cpe23.toString();
            Resource resource = additionalCPEModel.createResource(s.toString());

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

            resource.addProperty(CPE.CPE_VERSION, cpe2);
            resource.addProperty(CPE.PART, cpe3);
            resource.addProperty(CPE.VERSION, cpe6);
            resource.addProperty(CPE.UPDATE, cpe7);
            resource.addProperty(CPE.EDITION, cpe8);
            resource.addProperty(CPE.LANGUAGE, cpe9);
            resource.addProperty(CPE.SOFTWARE_EDITION, cpe10);
            resource.addProperty(CPE.TARGET_SOFTWARE, cpe11);
            resource.addProperty(CPE.TARGET_HARDWARE, cpe10);
            resource.addProperty(CPE.OTHER, cpe12);
        }
        return additionalCPEModel;
    }
}
