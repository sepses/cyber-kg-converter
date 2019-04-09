package ac.at.tuwien.ifs.sepses.processor.helper;

import ac.at.tuwien.ifs.sepses.rml.XMLParser;
import org.apache.jena.query.*;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.ResourceFactory;

import java.io.IOException;

public class QueryUtility {

    /**
     * check if CAPEC needs update (based on the CAPEC catalog iD)
     *
     * @param tempRML
     * @param xmlFile
     * @param endpoint
     * @param graph
     * @param catalogResource
     *
     * @return true if existing catalog id the same with the new catalog id
     * @throws IOException
     */
    public static boolean checkIsUpToDate(String tempRML, String xmlFile, String endpoint, String graph,
            Resource catalogResource) throws IOException {

        ParameterizedSparqlString queryString1 =
                new ParameterizedSparqlString("select ?s from ?graph where { ?s a ?catalog }");
        Resource graphResource = ResourceFactory.createResource(graph);
        queryString1.setParam("graph", graphResource);
        queryString1.setParam("catalog", catalogResource);
        QueryExecution qeQuery1 = QueryExecutionFactory.sparqlService(endpoint, queryString1.asQuery());

        ResultSet rs1 = qeQuery1.execSelect();
        String s1 = "";
        while (rs1.hasNext()) {
            QuerySolution qsQuery1 = rs1.nextSolution();
            RDFNode cat = qsQuery1.get("?s");
            s1 = cat.toString();
        }

        Model TempModel = XMLParser.Parse(xmlFile, tempRML);
        ParameterizedSparqlString stringQuery2 = new ParameterizedSparqlString("select ?s where { ?s a ?catalog }");
        stringQuery2.setParam("catalog", catalogResource);
        QueryExecution qeQuery2 = QueryExecutionFactory.create(stringQuery2.asQuery(), TempModel);

        ResultSet rs2 = qeQuery2.execSelect();
        String s2 = "";
        while (rs2.hasNext()) {
            QuerySolution qsQuery2 = rs2.nextSolution();
            RDFNode cat2 = qsQuery2.get("?s");
            s2 = cat2.toString();
        }

        return (s1.equals(s2));
    }

    /**
     * Counts how many instances are contained within the downloaded file
     *
     * @param model
     * @param cls
     *
     * @return string of instance count
     */
    public static Integer countInstance(Model model, Resource cls) {
        Integer count = 0;
        ParameterizedSparqlString queryString =
                new ParameterizedSparqlString("select (str(count(?s)) as ?c) where { ?s a ?cls }");
        queryString.setParam("cls", cls);
        QueryExecution queryExecution = QueryExecutionFactory.create(queryString.asQuery(), model);

        ResultSet resultSet = queryExecution.execSelect();
        while (resultSet.hasNext()) {
            QuerySolution querySolution = resultSet.nextSolution();
            RDFNode queryNode = querySolution.get("c");
            count = queryNode.asLiteral().getInt();
        }
        return count;

    }
}
