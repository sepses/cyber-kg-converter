package rmlparser;

import com.taxonic.carml.engine.RmlMapper;
import com.taxonic.carml.logical_source_resolver.JsonPathResolver;
import com.taxonic.carml.model.TriplesMap;
import com.taxonic.carml.util.RmlMappingLoader;
import com.taxonic.carml.vocab.Rdf;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.eclipse.rdf4j.model.Model;
import org.eclipse.rdf4j.rio.RDFFormat;
import org.eclipse.rdf4j.rio.Rio;

import java.io.*;
import java.util.Set;

public class JSONParser {

    public static org.apache.jena.rdf.model.Model Parse(String jsonFileName) throws IOException {
        // load RML file and all supporting functions
        InputStream is = CsvParser.class.getClassLoader().getResourceAsStream("rml/nvdcve-json.rml");
        Set<TriplesMap> mapping = RmlMappingLoader.build().load(RDFFormat.TURTLE, is);
        RmlMapper mapper = RmlMapper.newBuilder().setLogicalSourceResolver(Rdf.Ql.JsonPath, new JsonPathResolver()).build();

        // load input CSV file and convert it to RDF
        InputStream instances = new FileInputStream(jsonFileName);
        mapper.bindInputStream(instances);

        // write it out to an turtle file
        Model sesameModel = mapper.map(mapping);

        // create a temp file and return jena model
        File file = File.createTempFile("model", ".ttl");
        file.deleteOnExit();
        Rio.write(sesameModel, new FileOutputStream(file), RDFFormat.TURTLE); // write mapping
        org.apache.jena.rdf.model.Model jenaModel = org.apache.jena.rdf.model.ModelFactory.createDefaultModel();
        RDFDataMgr.read(jenaModel, new FileInputStream(file), Lang.TURTLE);

        return jenaModel;
    }
}
