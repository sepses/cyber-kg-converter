package ac.at.tuwien.ifs.sepses.rml;

import com.taxonic.carml.engine.RmlMapper;
import com.taxonic.carml.logical_source_resolver.XPathResolver;
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

public class XMLParser {

    public static org.apache.jena.rdf.model.Model Parse(String xmlFileName, String rmlFile) throws IOException {

        // load RML file and all supporting functions
        InputStream is = XMLParser.class.getClassLoader().getResourceAsStream(rmlFile);
        Set<TriplesMap> mapping = RmlMappingLoader.build().load(RDFFormat.TURTLE, is);
        RmlMapper mapper = RmlMapper.newBuilder().setLogicalSourceResolver(Rdf.Ql.XPath, new XPathResolver()).build();

        // load input file and convert it to RDF
        InputStream instances = new FileInputStream(xmlFileName);
        mapper.bindInputStream(instances);

        // write it out to an turtle file
        Model sesameModel = mapper.map(mapping);

        // //create a temp file and return jena model
        File file = File.createTempFile("model3", ".ttl");
        file.deleteOnExit();
        Rio.write(sesameModel, new FileOutputStream(file), RDFFormat.TURTLE); // write mapping
        org.apache.jena.rdf.model.Model jenaModel = org.apache.jena.rdf.model.ModelFactory.createDefaultModel();
        RDFDataMgr.read(jenaModel, new FileInputStream(file), Lang.TURTLE);

        return jenaModel;
    }
}
