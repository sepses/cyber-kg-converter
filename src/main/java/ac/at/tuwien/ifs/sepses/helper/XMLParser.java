package ac.at.tuwien.ifs.sepses.helper;

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

    /**
     * return turtle file name generated with caRML and RML mappings.
     *
     * @param xmlFileName
     * @param rmlFile
     * @return
     * @throws IOException
     */
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
        is.close();
        instances.close();

        // create a temp file and return jena model
        File file = File.createTempFile("model3", ".ttl");
        file.deleteOnExit();
        OutputStream tempOutput = new FileOutputStream(file);
        Rio.write(sesameModel, tempOutput, RDFFormat.TURTLE); // write mapping
        sesameModel.clear();
        tempOutput.flush();
        tempOutput.close();

        // create jena model
        Model model = ModelFactory.createDefaultModel();
        model.setNsPrefixes(Utility.getPrefixes());
        InputStream tempInput = new FileInputStream(file);
        RDFDataMgr.read(model, tempInput, Lang.TURTLE);
        tempInput.close();

        return model;
    }
}
