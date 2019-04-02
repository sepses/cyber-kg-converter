import ac.at.tuwien.ifs.sepses.rml.XMLParser;

import java.io.FileWriter;
import java.io.IOException;

public class TestParserXMLJena {

    public static void main(String[] args) throws Exception {

        String xmlFileName = "./input/cveyear/nvdcve-2.0-2003.xml";
        String RMLFile = "rml/nvdcvenew-complete.rml";
        org.apache.jena.rdf.model.Model testModel = XMLParser.Parse(xmlFileName, RMLFile);
        testModel.write(System.out, "TURTLE");
        String fileName = "output/cveyear/nvdcve-2.0-2003.ttl";
        FileWriter out = new FileWriter(fileName);
        try {
            testModel.write(out, "TURTLE");
        } finally {
            try {

                out.close();

            } catch (IOException closeException) {
                // ignore
            }
        }

    }

}


    
   


