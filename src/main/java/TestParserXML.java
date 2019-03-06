
import rmlparser.XMLParser;
import org.apache.commons.io.IOUtils;
import org.apache.jena.rdf.model.*;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.vocabulary.RDF;
import org.eclipse.rdf4j.common.io.IOUtil;
import org.eclipse.rdf4j.model.Model;
import org.eclipse.rdf4j.rio.RDFFormat;
import org.eclipse.rdf4j.rio.Rio;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;

public class TestParserXML {

    public static void main(String[] args) throws Exception {

        String XMLFile = "./input/official-cpe-dictionary_v2.3.xml";
        String fileName = XMLFile.substring(XMLFile.lastIndexOf("/") + 1);
        Model testModel = XMLParser.Parse(XMLFile);      
        Rio.write(testModel, System.out,RDFFormat.TURTLE);
        String fileNameOutput = "output/"+fileName+"_output.ttl";
        FileWriter out = new FileWriter(fileNameOutput);
        try {
        	Rio.write(testModel, out,RDFFormat.TURTLE );
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


    
   


