package ac.at.tuwien.ifs.sepses.vocab;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;

public class CAT {
	  /**
     * <p>The namespace of the vocabulary as a string</p>
     */
    public static final String NS = "http://w3id.org/sepses/vocab/ref/cat#";
    public static final String NS_INSTANCE = "http://w3id.org/sepses/resource/cat/";
    /**
     * <p>The RDF model that holds the vocabulary terms</p>
     */
    private static Model m_model = ModelFactory.createDefaultModel();
    /**
     * <p>The namespace of the vocabulary as a resource</p>
     */
    public static final Resource NAMESPACE = m_model.createResource(NS);
    public static final Property ACCOMPLISHES_TACTIC =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#accomplishesTactic");
    public static final Property HAS_CAPEC =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#hasCAPEC");
    public static final Property HAS_GROUP =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#hasGroup");
    public static final Property HAS_MITIGATION =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#hasMitigation");
    public static final Property HAS_SOFTWARE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#hasSoftware");
    public static final Property HAS_TECHNIQUE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#hasTechnique");
    public static final Property IMPLEMENTS_TECHNIQUE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#implementsTechnique");
    public static final Property PREVENTS_TECHNIQUE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#preventsTechnique");
    public static final Property USES_SOFTWARE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#usesSoftware");
    public static final Property USES_TECHNIQUE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#usesTechnique");
    public static final Property ASSOSIATED_GROUP =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#associatedGroup");
    public static final Property DATA_SOURCE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#dataSource");
    public static final Property DETECTION =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#detection");
    public static final Property PERMISSION_REQUIRED =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#permissionRequired");
    public static final Property PLATFORM =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#platform");
    public static final Property SYSTEM_REQUIREMENT =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/cat#systemRequirement");
    
    public static final Resource GROUP = m_model.createResource("http://w3id.org/sepses/vocab/ref/cat#Group");
    public static final Resource MITIGATION = m_model.createResource("http://w3id.org/sepses/vocab/ref/cat#Mitigation");
    public static final Resource SOFTWARE = m_model.createResource("http://w3id.org/sepses/vocab/ref/cat#Software");
    public static final Resource SUBTECHNIQUE = m_model.createResource("http://w3id.org/sepses/vocab/ref/cat#SubTechnique");
    public static final Resource TACTIC = m_model.createResource("http://w3id.org/sepses/vocab/ref/cat#Tactic");
    public static final Resource TECHNIQUE = m_model.createResource("http://w3id.org/sepses/vocab/ref/cat#Technique");
    public static final Resource ATTACK_PATTERN = m_model.createResource("http://w3id.org/sepses/vocab/ref/cat#attack-pattern");
        
    
    
    
    
    
    /**
     * <p>The namespace of the vocabulary as a string</p>
     *
     * @see #NS
     */
    public static String getURI() {
        return NS;
    }

}
