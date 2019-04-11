package ac.at.tuwien.ifs.sepses.rml;

import ac.at.tuwien.ifs.sepses.helper.ModelUtility;
import com.taxonic.carml.engine.RmlMapper;
import com.taxonic.carml.logical_source_resolver.XPathResolver;
import com.taxonic.carml.model.TriplesMap;
import com.taxonic.carml.util.RmlMappingLoader;
import com.taxonic.carml.vocab.Rdf;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.eclipse.rdf4j.rio.RDFFormat;
import org.eclipse.rdf4j.rio.Rio;

import java.io.*;
import java.util.Set;

public class XMLParser {

    public static Model Parse(String xmlFileName, String rmlFile) throws IOException {

        // load RML file and all supporting functions
        InputStream is = XMLParser.class.getClassLoader().getResourceAsStream(rmlFile);
        Set<TriplesMap> mapping = RmlMappingLoader.build().load(RDFFormat.TURTLE, is);
        RmlMapper mapper = RmlMapper.newBuilder().setLogicalSourceResolver(Rdf.Ql.XPath, new XPathResolver()).build();

        // load input file and convert it to RDF
        InputStream instances = new FileInputStream(xmlFileName);
        mapper.bindInputStream(instances);

        // write it out to an turtle file
        org.eclipse.rdf4j.model.Model sesameModel = mapper.map(mapping);

        // create a temp file and return jena model
        File file = File.createTempFile("model3", ".ttl");
        file.deleteOnExit();
        Rio.write(sesameModel, new FileOutputStream(file), RDFFormat.TURTLE); // write mapping

        // create jena model
        Model model = ModelFactory.createDefaultModel();
        model.setNsPrefixes(ModelUtility.getPrefixes());
        RDFDataMgr.read(model, new FileInputStream(file), Lang.TURTLE);

        return model;
    }
}
