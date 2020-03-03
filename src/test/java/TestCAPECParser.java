import ac.at.tuwien.ifs.sepses.parser.Parser;
import ac.at.tuwien.ifs.sepses.parser.impl.CAPECParser;
import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.ResourceFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.topbraid.shacl.validation.ValidationUtil;
import org.topbraid.shacl.vocabulary.SH;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class TestCAPECParser {

    private static final Logger log = LoggerFactory.getLogger(TestCAPECParser.class);

    private static Properties properties = new Properties();
    private static String endpoint;
    private static Parser parser;
    private static Model constraints = ModelFactory.createDefaultModel();

    @BeforeClass public static void beforeClass() throws IOException {
        FileInputStream ip = new FileInputStream("config.properties");
        properties.load(ip);
        ip.close();
        endpoint = properties.getProperty("SparqlEndpoint");
        parser = new CAPECParser(properties);
        InputStream is = TestCAPECParser.class.getClassLoader().getResourceAsStream("shacl/capec.ttl");
        RDFDataMgr.read(constraints, is, Lang.TURTLE);
        is.close();
    }

    @Test public void testCAPECConfig() {
        ParameterizedSparqlString query = new ParameterizedSparqlString("ASK WHERE { ?s ?p ?o }");
        QueryExecution queryExecution = QueryExecutionFactory.sparqlService(endpoint, query.asQuery());
        queryExecution.execAsk();
    }

    @Test public void testCAPECParse() throws IOException {
        Long start = System.currentTimeMillis() / 1000;
        log.info("CAPEC constraint check starts");
        Model model = parser.getModelFromLastUpdate();
        Resource result = ValidationUtil.validateModel(model, constraints, false);
        RDFDataMgr.write(System.out, result.getModel(), Lang.TURTLE);
        Long end = System.currentTimeMillis() / 1000;
        log.info("CAPEC constraint check finished in " + (start - end) + " seconds");
        Assert.assertTrue(result.getModel().contains(null, SH.conforms, ResourceFactory.createTypedLiteral(true)));
    }

}
