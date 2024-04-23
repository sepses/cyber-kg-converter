package ac.at.tuwien.ifs.sepses.vocab;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;

public class CAT {
	  /**
     * <p>The namespace of the vocabulary as a string</p>
     */
    public static final String NS = "http://w3id.org/sepses/vocab/ref/attack#";
    public static final String NS_INSTANCE = "http://w3id.org/sepses/resource/attack/";
    /**
     * <p>The RDF model that holds the vocabulary terms</p>
     */
    private static Model m_model = ModelFactory.createDefaultModel();
    /**
     * <p>The namespace of the vocabulary as a resource</p>
     */
    public static final Resource NAMESPACE = m_model.createResource(NS);
    public static final Property ACCOMPLISHES_TACTIC =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#accomplishesTactic");
    public static final Property HAS_CAPEC =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#hasCAPEC");
    public static final Property HAS_GROUP =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#hasGroup");
    public static final Property HAS_MITIGATION =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#hasMitigation");
    public static final Property HAS_SOFTWARE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#hasSoftware");
    public static final Property HAS_TECHNIQUE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#hasTechnique");
    public static final Property IMPLEMENTS_TECHNIQUE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#implementsTechnique");
    public static final Property PREVENTS_TECHNIQUE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#preventsTechnique");
    public static final Property USES_SOFTWARE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#usesSoftware");
    public static final Property USES_MALWARE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#usesMalware");
    public static final Property USES_TECHNIQUE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#usesTechnique");
    public static final Property TARGETS_ASSET =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#targetsAsset");
    public static final Property ASSOSIATED_GROUP =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#associatedGroup");
    public static final Property DATA_SOURCE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#dataSource");
    public static final Property DATASOURCE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#DataSource");
    public static final Property DETECTION =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#detection");
    public static final Property PERMISSION_REQUIRED =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#permissionRequired");
    public static final Property PLATFORM =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#platform");
    public static final Property SYSTEM_REQUIREMENT =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/attack#systemRequirement");
    
    public static final Resource GROUP = m_model.createResource("http://w3id.org/sepses/vocab/ref/attack#Group");
    public static final Resource MITIGATION = m_model.createResource("http://w3id.org/sepses/vocab/ref/attack#Mitigation");
    public static final Resource SOFTWARE = m_model.createResource("http://w3id.org/sepses/vocab/ref/attack#Software");
    public static final Resource MALWARE = m_model.createResource("http://w3id.org/sepses/vocab/ref/attack#Malware");
    public static final Resource SUBTECHNIQUE = m_model.createResource("http://w3id.org/sepses/vocab/ref/attack#SubTechnique");
    public static final Resource TACTIC = m_model.createResource("http://w3id.org/sepses/vocab/ref/attack#Tactic");
    public static final Resource TECHNIQUE = m_model.createResource("http://w3id.org/sepses/vocab/ref/attack#Technique");
    public static final Resource ATTACK_PATTERN = m_model.createResource("http://w3id.org/sepses/vocab/ref/attack#attack-pattern");
    public static final Resource ASSET = m_model.createResource("http://w3id.org/sepses/vocab/ref/attack#Asset");
    public static final Resource CAMPAIGN = m_model.createResource("http://w3id.org/sepses/vocab/ref/attack#Campaign");
    public static final Resource DATA_COMPONENT = m_model.createResource("http://w3id.org/sepses/vocab/ref/attack#DataComponent");
        
    
    
    
    
    
    /**
     * <p>The namespace of the vocabulary as a string</p>
     *
     * @see #NS
     */
    public static String getURI() {
        return NS;
    }

}
