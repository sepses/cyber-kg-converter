package ac.at.tuwien.ifs.sepses.parser.tool;

import ac.at.tuwien.ifs.sepses.vocab.CAPEC;
import ac.at.tuwien.ifs.sepses.vocab.CPE;
import ac.at.tuwien.ifs.sepses.vocab.CVE;
import ac.at.tuwien.ifs.sepses.vocab.CWE;
import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.ResourceFactory;
import org.apache.jena.update.UpdateAction;
import org.apache.jena.update.UpdateFactory;
import org.apache.jena.update.UpdateRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Add correct links between classes in a model
 */
public class Linker {

    private static final Logger log = LoggerFactory.getLogger(Linker.class);

    public static void updateCveLinks(Model cveModel) {
        log.info("generating correct CVE links");

        Property isCpeOf = ResourceFactory.createProperty(CVE.NS + "isCpeOf");
        Property isLogicalTestFactRefOf = ResourceFactory.createProperty(CPE.NS + "isLogicalTestFactRefOf");
        Property isVulnerableConfigurationOf = ResourceFactory.createProperty(CPE.NS + "isVulnerableConfigurationOf");

        executeLinksUpdate(cveModel, isCpeOf, CVE.HAS_CPE);
        executeLinksUpdate(cveModel, isLogicalTestFactRefOf, CPE.HAS_LOGICAL_TEST_FACT_REF);
        executeLinksUpdate(cveModel, isVulnerableConfigurationOf, CVE.HAS_VULNERABLE_CONFIGURATION);

        log.info("generating correct CVE links ... done");
    }

    public static void updateCweLinks(Model cweModel) {
        log.info("generating correct CWE links");

        Property isModificationHistoryOf = ResourceFactory.createProperty(CWE.NS + "isModificationHistoryOf");
        Property isSubmissionHistoryOf = ResourceFactory.createProperty(CWE.NS + "isSubmissionHistoryOf");
        Property isModeOfIntroductionOf = ResourceFactory.createProperty(CWE.NS + "isModeOfIntroductionOf");
        Property isDetectionMethodOf = ResourceFactory.createProperty(CWE.NS + "isDetectionMethodOf");
        Property isPotentialMitigationOf = ResourceFactory.createProperty(CWE.NS + "isPotentialMitigationOf");
        Property isCommonSequenceOf = ResourceFactory.createProperty(CWE.NS + "isCommonConsequenceOf");
        Property isRelatedWeaknessOf = ResourceFactory.createProperty(CWE.NS + "isRelatedWeaknessOf");

        executeLinksUpdate(cweModel, isModificationHistoryOf, CWE.HAS_MODIFICATION_HISTORY);
        executeLinksUpdate(cweModel, isSubmissionHistoryOf, CWE.HAS_SUBMISSION_HISTORY);
        executeLinksUpdate(cweModel, isModeOfIntroductionOf, CWE.HAS_MODE_OF_INTRODUCTION);
        executeLinksUpdate(cweModel, isDetectionMethodOf, CWE.HAS_DETECTION_METHOD);
        executeLinksUpdate(cweModel, isPotentialMitigationOf, CWE.HAS_POTENTIAL_MITIGATION);
        executeLinksUpdate(cweModel, isCommonSequenceOf, CWE.HAS_COMMON_CONSEQUENCE);
        executeLinksUpdate(cweModel, isRelatedWeaknessOf, CWE.HAS_RELATED_WEAKNESS);

        log.info("generating correct CVE links ... done");
    }

    public static void updateCapecLinks(Model capecModel) {
        log.info("generating correct CAPEC links");

        Property isModificationHistoryOf = ResourceFactory.createProperty(CAPEC.NS + "isModificationHistoryOf");
        Property isSubmissionHistoryOf = ResourceFactory.createProperty(CAPEC.NS + "isSubmissionHistoryOf");
        Property isSkillRequiredFor = ResourceFactory.createProperty(CAPEC.NS + "isSkillRequiredFor");
        Property isRelatedAttackPatternOf = ResourceFactory.createProperty(CAPEC.NS + "isRelatedAttackPatternOf");
        Property isConsequenceOf = ResourceFactory.createProperty(CAPEC.NS + "isConsequenceOf");
        Property isExecutionFlowOf = ResourceFactory.createProperty(CAPEC.NS + "isExecutionFlowOf");

        executeLinksUpdate(capecModel, isModificationHistoryOf, CAPEC.HAS_MODIFICATION_HISTORY);
        executeLinksUpdate(capecModel, isSubmissionHistoryOf, CAPEC.HAS_SUBMISSION_HISTORY);
        executeLinksUpdate(capecModel, isSkillRequiredFor, CAPEC.HAS_SKILL_REQUIRED);
        executeLinksUpdate(capecModel, isRelatedAttackPatternOf, CAPEC.HAS_RELATED_ATTACK_PATTERN);
        executeLinksUpdate(capecModel, isConsequenceOf, CAPEC.HAS_CONSEQUENCE);
        executeLinksUpdate(capecModel, isExecutionFlowOf, CAPEC.HAS_CONSEQUENCE);

        log.info("generating correct CAPEC links ... done");
    }

    public static void executeLinksUpdate(Model model, Property p1, Property p2) {

        ParameterizedSparqlString update =
                new ParameterizedSparqlString("DELETE { ?a ?p1 ?b } INSERT { ?b ?p2 ?a } WHERE { ?a ?p1 ?b } ");
        update.setNsPrefixes(model.getNsPrefixMap());
        update.setParam("p1", p1);
        update.setParam("p2", p2);

        UpdateRequest updateRequest = UpdateFactory.create(update.toString());
        UpdateAction.execute(updateRequest, model);

    }

}
