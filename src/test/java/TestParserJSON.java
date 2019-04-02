import ac.at.tuwien.ifs.sepses.rml.JSONParser;
import org.apache.jena.rdf.model.Model;

import java.io.FileWriter;
import java.io.IOException;

public class TestParserJSON {

    public static void main(String[] args) throws Exception {

        String XMLFile = "./input/nvdcve-1.0-2018.json";

        Model testModel = JSONParser.Parse(XMLFile);

        testModel.write(System.out, "TURTLE");

        String fileName = "output/nvdcve-1.0-2018.ttl";
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


    
   


