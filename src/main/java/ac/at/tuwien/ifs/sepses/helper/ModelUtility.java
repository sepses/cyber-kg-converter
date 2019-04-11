package ac.at.tuwien.ifs.sepses.helper;

import ac.at.tuwien.ifs.sepses.vocab.*;
import org.apache.jena.vocabulary.DCTerms;
import org.apache.jena.vocabulary.OWL;
import org.eclipse.rdf4j.model.vocabulary.RDF;
import org.eclipse.rdf4j.model.vocabulary.RDFS;

import java.util.HashMap;
import java.util.Map;

public class ModelUtility {

    public static Map<String, String> getPrefixes() {
        Map<String, String> prefixes = new HashMap<>();

        // General
        prefixes.put("rdf", RDF.NAMESPACE);
        prefixes.put("rdfs", RDFS.NAMESPACE);
        prefixes.put("owl", OWL.NS);
        prefixes.put("dct", DCTerms.NS);

        // SEPSES classes
        prefixes.put("cpe", CPE.NS);
        prefixes.put("cve", CVE.NS);
        prefixes.put("cvss", CVSS.NS);
        prefixes.put("capec", CAPEC.NS);
        prefixes.put("cwe", CWE.NS);

        // SEPSES resources
        prefixes.put("cpe-res", CPE.NS_INSTANCE);
        prefixes.put("cve-res", CVE.NS_INSTANCE);
        prefixes.put("cvss-res", CVSS.NS_INSTANCE);
        prefixes.put("capec-res", CAPEC.NS_INSTANCE);
        prefixes.put("cwe-res", CWE.NS_INSTANCE);

        return prefixes;
    }
}
