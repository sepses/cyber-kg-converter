import ac.at.tuwien.ifs.sepses.rml.XMLParser;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;

import java.io.FileWriter;
import java.io.IOException;

public class TestParserXML {

    public static void main(String[] args) throws Exception {

        String XMLFile = "./input/official-cpe-dictionary_v2.3.xml";
        String fileName = XMLFile.substring(XMLFile.lastIndexOf("/") + 1);
        Model testModel = XMLParser.Parse(XMLFile, "rml/cpe-xml.rml");
        RDFDataMgr.write(System.out, testModel, Lang.TURTLE);
        String fileNameOutput = "output/" + fileName + "_output.ttl";
        FileWriter out = new FileWriter(fileNameOutput);
        try {
            RDFDataMgr.write(out, testModel, Lang.TURTLE);
        } finally {
            try {
                out.close();
            } catch (IOException closeException) {
                // ignore
            }
        }

    }

}


    
   


