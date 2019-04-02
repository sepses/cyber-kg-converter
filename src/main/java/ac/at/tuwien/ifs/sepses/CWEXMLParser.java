package ac.at.tuwien.ifs.sepses;

import ac.at.tuwien.ifs.sepses.linking.CWELinking;
import org.apache.jena.rdf.model.ModelFactory;
import ac.at.tuwien.ifs.sepses.rml.XMLParserJena;

import java.io.FileWriter;

public class CWEXMLParser {

    public static void main(String[] args) throws Exception {

        String xmlFileName = "./input/1000.xml";
        String RMLFile = "rml/nvdcvenew-complete.rml";
        org.apache.jena.rdf.model.Model CWEModel = XMLParserJena.Parse(xmlFileName, RMLFile);
        String fileName = xmlFileName.substring(xmlFileName.lastIndexOf("/") + 1);

        CWEModel.write(System.out, "TURTLE");
        System.exit(0);

        org.apache.jena.rdf.model.Model CAPECModel = ModelFactory.createDefaultModel();
        CAPECModel.read("output/1000-capec_o.ttl");

        org.apache.jena.rdf.model.Model testCWELinking = CWELinking.generateLinking(CWEModel, CAPECModel, fileName);

        //CWEModel.write( System.out,"TURTLE");
        //testCWELinking.write( System.out,"TURTLE");

        //call CWELinking
        String LinkingFileNameCWE = "output/ac.at.tuwien.ifs.sepses.linking/" + fileName + "-linkingCWETOCAPEC.ttl";
        String fileNameCWE = "output/" + fileName + ".ttl";

        FileWriter outCWE = new FileWriter(fileNameCWE);
        FileWriter outCWELinking = new FileWriter(LinkingFileNameCWE);

        try {
            CWEModel.write(outCWE, "TURTLE");
            testCWELinking.write(outCWELinking, "TURTLE");

        } finally {
            CWEModel.close();
            CAPECModel.close();
        }

    }

}


    
   


