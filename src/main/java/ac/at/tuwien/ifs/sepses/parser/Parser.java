package ac.at.tuwien.ifs.sepses.parser;

import org.apache.jena.rdf.model.Model;

import java.io.IOException;

public interface Parser {

    /**
     * the main function in three steps: (1) getModelFromLastUpdate; (2) saveModelToFile; and (3) storeFileInRepo.
     * detail in implementation might be different for different resource.
     *
     * @return Jena's RDF model
     */
    public void parse() throws IOException;

    /**
     * load the latest version of cyber-security resource data from online resource(s).
     *
     * @return Jena's RDF model
     */
    public Model getModelFromLastUpdate() throws IOException;

    /**
     * store a cyber-security model file within designated triplestore.
     *
     * @param model model to be saved into output folder
     */
    public String saveModelToFile(Model model);

    /**
     * store a cyber-security model within designated triplestore based on the property attributes.
     *
     * @param filename link to the model file
     */
    public void storeFileInRepo(String filename);

}
