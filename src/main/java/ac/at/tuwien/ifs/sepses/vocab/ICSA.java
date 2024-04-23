package ac.at.tuwien.ifs.sepses.vocab;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;

public class ICSA {
	  /**
     * <p>The namespace of the vocabulary as a string</p>
     */
    public static final String NS = "http://w3id.org/sepses/vocab/ref/icsa#";
    public static final String NS_INSTANCE = "http://w3id.org/sepses/resource/icsa/";
    /**
     * <p>The RDF model that holds the vocabulary terms</p>
     */
    private static Model m_model = ModelFactory.createDefaultModel();
    /**
     * <p>The namespace of the vocabulary as a resource</p>
     */
    public static final Resource NAMESPACE = m_model.createResource(NS);
    public static final Property HAS_VENDOR =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/icsa#hasVendor");
    public static final Property vendor =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/icsa#vendor");
    public static final Property companyHeadquarter =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/icsa#companyHeadquarter");
    public static final Property productDistribution =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/icsa#productDistribution");
    public static final Property criticalInfrastructureSector =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/icsa#criticalInfrastructureSector");
    public static final Property product =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/icsa#product");
    public static final Property cveNumber =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/icsa#cveNumber");
    public static final Property cweNumber =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/icsa#cweNumber");
    public static final Property HAS_CVE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/icsa#hasCVE");
    public static final Property HAS_CWE =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/icsa#hasCWE");
    public static final Property HAS_COMPANY_HEADQUARTER =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/icsa#hasCompanyHeadquarter");
    public static final Property HAS_CRITICAL_INFRASTRUCTURE_SECTOR =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/icsa#hasCriticalInfrastructureSector");
    public static final Property HAS_PRODUCT =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/icsa#hasProduct");
    public static final Property HAS_PRODUCT_DISTRIBUTION =
            m_model.createProperty("http://w3id.org/sepses/vocab/ref/icsa#hasProductDistribution");
    
    
    public static final Resource ICSA = m_model.createResource("http://w3id.org/sepses/vocab/ref/icsa#ICSA");
    public static final Resource PRODUCT = m_model.createResource("http://w3id.org/sepses/vocab/ref/icsa#Product");
    public static final Resource VENDOR = m_model.createResource("http://w3id.org/sepses/vocab/ref/icsa#Vendor");
    public static final Resource PRODUCT_DISTRIBUTION = m_model.createResource("http://w3id.org/sepses/vocab/ref/icsa#ProductDistribution");
    public static final Resource COMPANY_HEADQUARTER = m_model.createResource("http://w3id.org/sepses/vocab/ref/icsa#CompanyHeadquarter");
    public static final Resource CRITICAL_INFRASTRUCTURE_SECTOR = m_model.createResource("http://w3id.org/sepses/vocab/ref/icsa#CriticalInfrastructureSector");
    
    /**
     * <p>The namespace of the vocabulary as a string</p>
     *
     * @see #NS
     */
    public static String getURI() {
        return NS;
    }

}
