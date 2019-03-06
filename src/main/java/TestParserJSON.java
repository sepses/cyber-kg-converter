
import rmlparser.JSONParser;
import org.apache.commons.io.IOUtils;
import org.apache.jena.rdf.model.*;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.vocabulary.RDF;
import org.eclipse.rdf4j.common.io.IOUtil;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;

public class TestParserJSON {

    public static void main(String[] args) throws Exception {

        String XMLFile = "./input/nvdcve-1.0-2018.json";

        Model testModel = JSONParser.Parse(XMLFile);
        
        testModel.write(System.out,"TURTLE");      
        
        String fileName = "output/nvdcve-1.0-2018.ttl";
        FileWriter out = new FileWriter( fileName );
        try {
        	testModel.write(out, "TURTLE" );
        }
        finally {
           try {
        	 
               out.close();
               
           }
           catch (IOException closeException) {
               // ignore
           }
        }

    }
        
       
    }


    
   


